# keyload

[![Go Reference](https://pkg.go.dev/badge/github.com/rossedman/keyload.svg)](https://pkg.go.dev/github.com/rossedman/keyload)

keyload is a Go library that hot-reloads TLS material in both directions:
leaf certificates and keys, and the CA bundles used to verify peers. It
validates every reload before using it, keeps serving the last good material
when a reload fails, and never needs a restart. It is built for
cert-manager-style rotation of short-lived certificates and mTLS.

The core module depends on nothing but the standard library.

```
go get github.com/rossedman/keyload
go get github.com/rossedman/keyload/grpccreds   # optional, for grpc-go
```

## Why

`crypto/tls` lets you swap a leaf certificate per handshake
(`GetCertificate`, `GetClientCertificate`). There is no matching hook for the
trust side on clients: `RootCAs` is fixed once the config is in use, and
`x509.CertPool` is not safe to change while handshakes read it
([golang/go#70946](https://github.com/golang/go/issues/70946)). Requests for
dynamic `RootCAs`/`ClientCAs` have been open for years
([#16066](https://github.com/golang/go/issues/16066),
[#22836](https://github.com/golang/go/issues/22836)), and the common
workaround, `InsecureSkipVerify` plus hand-written verification, is easy to
get subtly wrong ([#64796](https://github.com/golang/go/issues/64796)).
Meanwhile a bad certificate pushed to a pod tends to crash-loop it instead of
falling back to the old one
([argocd-agent#1057](https://github.com/argoproj-labs/argocd-agent/issues/1057)).

## Usage

```go
r, err := keyload.New(ctx, keyload.FromFiles(keyload.Files{
    Cert: "/tls/tls.crt", Key: "/tls/tls.key",
    Roots: "/tls/ca.crt", ClientCAs: "/tls/ca.crt",
}), keyload.MinRemaining(time.Hour))
if err != nil {
    log.Fatal(err) // the first load must be valid
}
defer r.Close()

// Server: certificates and client CAs follow reloads.
srv := &http.Server{TLSConfig: r.ServerConfig(&tls.Config{
    ClientAuth: tls.RequireAndVerifyClientCert,
    NextProtos: []string{"h2", "http/1.1"}, // set here for HTTP/2, see below
})}

// Client: a fresh tls.Config with the current roots for every connection.
tr := &http.Transport{ForceAttemptHTTP2: true}
if err := r.ConfigureTransport(tr, &tls.Config{}); err != nil {
    log.Fatal(err) // refuses transports that use an HTTPS proxy
}
```

gRPC:

```go
creds := grpccreds.New(r, grpccreds.WithTLSConfig(&tls.Config{
    ClientAuth: tls.RequireAndVerifyClientCert,
}))
s := grpc.NewServer(grpc.Creds(creds))
cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(grpccreds.New(r)))
```

## How it works

All material lives in one immutable `Snapshot`, swapped with
`atomic.Pointer`. Handshakes read the current snapshot; reloads build a new
one off to the side and swap it in only after it passes validation. Nothing is
mutated in place, which removes the `CertPool` race entirely.

A reload:

1. is triggered by a file change, a signal, a timer or a call to `Reload`;
2. reads every source file, retrying up to 3 times with backoff if a read
   fails or the files look mid-write (truncated PEM, key not matching
   certificate);
3. validates: the key matches the leaf; every certificate in the leaf chain
   is inside its validity window, with an optional minimum remaining lifetime
   (`MinRemaining`); optionally the leaf chains to the new roots
   (`RequireChain`); each configured CA bundle has at least one certificate;
4. builds fresh `CertPool`s and a new snapshot with `Generation + 1`;
5. swaps it in. On any failure the old snapshot stays, an error event is
   emitted and a failure counter goes up.

Reloading unchanged material is a no-op, so frequent triggers are cheap.

### Integration modes

| Mode | For | How | Verification |
|---|---|---|---|
| `ServerConfig` | any `crypto/tls` server | `GetConfigForClient` returns a config built from the current snapshot | stdlib |
| `DialTLSContext` / `ConfigureTransport` | `http.Transport`, raw TLS dials | fresh `tls.Config` per connection with current `RootCAs` | stdlib |
| `grpccreds` | grpc-go clients and servers | `TransportCredentials` building TLS credentials from the current snapshot | stdlib |
| `ClientConfig` ("Config mode") | libraries that only take a `*tls.Config` | `InsecureSkipVerify` plus `VerifyConnection` against the current roots | keyload, matching stdlib |

Notes:

- **Server mode** builds one config per snapshot generation and caches it.
  It is cloned from your base config, so session ticket keys, cipher suites
  and `ClientAuth` carry over and session resumption keeps working across
  reloads. Resumed sessions have their client certificate re-checked against
  the current client CAs, so removing a CA also stops its clients from
  resuming old sessions. Handshakes use configs built from `base`, so set
  `NextProtos` there: `http.Server` and `httptest` add `h2` to a copy of the
  config, which keyload does not see.
- **Dialer mode** doesn't work through an HTTPS proxy, because
  `http.Transport` does its own TLS with `TLSClientConfig` for proxied
  requests. `ConfigureTransport` detects a configured proxy and returns
  `ErrProxyConfigured`. Use Config mode there.
- **Config mode** is the only place keyload verifies certificates itself. It
  refuses to build without `ServerName`, the classic `InsecureSkipVerify`
  bug. It verifies with `x509.Certificate.Verify` and the same options as
  crypto/tls (snapshot roots, peer intermediates, `DNSName = ServerName`,
  `ServerAuth`, the config's clock), on every handshake including resumed
  ones, and chains your own `VerifyConnection` after its own.
  `ConnectionState.VerifiedChains` is empty in this mode.

### Sources and triggers

- `FromFiles(Files{...})` reads PEM files and watches their directories with
  inotify. Watching directories and following symlink targets handles the
  Kubernetes Secret volume `..data` symlink swap. Bursts of events are
  debounced. On NFS, FUSE, SMB and similar filesystems, when inotify limits
  are hit, or on non-Linux systems, it polls every 30 seconds instead.
- `OnSignal(syscall.SIGHUP)`, `PollEvery(d)` and `r.Reload(ctx)` for manual
  control.
- Any other `Source` (Vault, a secrets API) just returns raw PEM in a
  `Material`, and may implement `Watcher` to push change notifications.

### CA rotation overlap

With `OverlapWindow(24 * time.Hour)`, a CA that disappears from a bundle stays
in the pool for 24 hours after it was removed. Peers holding certificates from
the outgoing CA keep working while they rotate. When the window ends the CA is
dropped automatically.

### Observability

`OnReload(func(Event))` reports every reload that changed the snapshot or
failed: the trigger, the result, the generation, the rejection reason
(naming the file) and the subjects and serials that were added or removed.
Events never contain key material.

`MetricsHandler(r)` serves Prometheus text format without a client library:

| Metric | Meaning |
|---|---|
| `keyload_generation` | current snapshot generation |
| `keyload_reload_total{result}` | `success`, `invalid`, `read_error` |
| `keyload_cert_not_after_seconds{role}` | expiry of the leaf chain and of the earliest CA in each bundle (`leaf`, `roots`, `client_cas`), so alerts can fire before expiry |
| `keyload_last_success_timestamp_seconds` | catches a watcher that silently stopped |

`r.Stats()` returns the same numbers for other metrics systems.

## Testing

- **Rotation under load**: leaf, roots and client CAs are rotated on both
  sides mid-traffic for HTTP/1.1, HTTP/2 and gRPC, with a full handshake per
  request; the tests require zero failures.
- **Bad-reload drills**: truncated PEM, mismatched key, expired and
  not-yet-valid leaves, too-short lifetime, empty bundles, half-written files,
  chain mismatch and missing files. Each must keep the old snapshot and
  report the right reason.
- **Kubernetes Secret volume**: the kubelet's `..data` symlink swap is
  reproduced on a real filesystem and watched with inotify.
- **Differential verification**: 2,000 generated chains (wrong host, IP SANs,
  expired intermediates, wrong EKU, name constraints, missing intermediates,
  untrusted roots) are verified by both crypto/tls and Config mode over real
  handshakes; any disagreement fails the build.
- **Fuzzing** of the PEM parsing and validation path (`FuzzParseMaterial`).

```
go test -race ./...
(cd grpccreds && go test -race ./...)
go test -run '^$' -fuzz FuzzParseMaterial -fuzztime 1m .
```

## Status

Pre-1.0. The API may still change. Config mode should get an external
security review before v1.0; see [SECURITY.md](SECURITY.md).

Not in scope: issuing or renewing certificates (ACME, cert-manager and Vault
PKI do that; keyload consumes what they write), revocation checking (OCSP,
CRLs), and replacing SPIFFE (teams on SPIRE should use go-spiffe).

## License

MIT
