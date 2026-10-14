# keyload

[![CI](https://github.com/rossedman/keyload/actions/workflows/ci.yml/badge.svg)](https://github.com/rossedman/keyload/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rossedman/keyload.svg)](https://pkg.go.dev/github.com/rossedman/keyload)

Go library for **reloading TLS certificates and CA bundles at runtime**. When cert-manager (or anything else) rotates your certificates, servers and clients pick up the new files on their next handshake, with no restart.

Use it for short-lived certificates and mTLS, where both sides need to follow a rotation: the certificate you present *and* the CAs you trust.

- Reloads both directions: your certificate and key, and the CA bundles used to verify servers and clients
- Never applies bad material: an expired certificate, a mismatched key or a half-written file is rejected, and the last good one keeps serving
- Works with Kubernetes Secret volumes out of the box (including the `..data` symlink swap)
- CA rotation without an outage: keep outgoing CAs trusted for an overlap window
- crypto/tls still does the verification; keyload doesn't need `InsecureSkipVerify` for servers, HTTP clients or gRPC
- Prometheus metrics and reload events, so you hear about a bad certificate before it expires
- No dependencies outside the standard library (gRPC support is a separate module)

```sh
go get github.com/rossedman/keyload
```

## Quick start

```go
r, err := keyload.New(keyload.Files{
	Cert:      "/tls/tls.crt",
	Key:       "/tls/tls.key",
	Roots:     "/tls/ca.crt", // CAs to verify servers
	ClientCAs: "/tls/ca.crt", // CAs to verify clients
})
if err != nil {
	log.Fatal(err) // the first load must be valid
}
defer r.Close()

// Server: the certificate and client CAs follow reloads.
srv := &http.Server{Addr: ":8443", TLSConfig: r.ServerConfig(&tls.Config{
	ClientAuth: tls.RequireAndVerifyClientCert,
	NextProtos: []string{"h2", "http/1.1"}, // for HTTP/2
})}
go srv.ListenAndServeTLS("", "") // no file names: the certificate comes from TLSConfig

// Client: every connection uses the current certificate and roots.
tr := &http.Transport{ForceAttemptHTTP2: true}
if err := r.ConfigureTransport(tr, nil); err != nil {
	log.Fatal(err)
}
```

That's the whole setup. When the files change, keyload validates them and swaps them in. When they're bad, it keeps the old ones and tells you:

```go
keyload.New(files, keyload.OnReload(func(ev keyload.Event) {
	if ev.Err != nil {
		log.Printf("TLS reload rejected, still serving generation %d: %v", ev.Generation, ev.Err)
	}
}))
```

No certificates to try it with? `gencerts` writes a throwaway CA and a certificate for `localhost`, laid out like a cert-manager Secret, and rotates it on demand. No clone needed:

```sh
go run github.com/rossedman/keyload/examples/gencerts@latest -dir ./certs          # ca.crt, tls.crt, tls.key
go run github.com/rossedman/keyload/examples/gencerts@latest -dir ./certs -rotate  # a new certificate
```

📖 **[Getting started](docs/getting-started.md)** walks through installing keyload, running a server and client, rotating and breaking certificates while they run, and testing your code. **Docs and an interactive reload simulator: https://rossedman.github.io/keyload/**

## Examples

Each example is a small runnable program: `go run ./examples/<name>` in a clone, or `go run github.com/rossedman/keyload/examples/<name>@latest` without one. The commands to try it are at the top of each file. `gencerts` makes throwaway certificates to try them with.

| Example | Shows |
|---|---|
| [`gencerts`](examples/gencerts/main.go) | Writes a demo CA and certificate, and rotates the certificate on demand |
| [`quickstart`](examples/quickstart/main.go) | The quick start as a program: an mTLS server and a client calling it every second. Its [tests](examples/quickstart/keyload_test.go) show how to test code that uses keyload |
| [`server`](examples/server/main.go) | An mTLS HTTPS server whose certificate and client CAs reload, with `SIGHUP` for on-demand reloads |
| [`client`](examples/client/main.go) | An mTLS HTTP client whose certificate and trusted CAs reload |
| [`proxy`](examples/proxy/main.go) | An HTTPS client behind an HTTP proxy, using Config mode |
| [`metrics`](examples/metrics/main.go) | Prometheus metrics, structured reload logs and alerting rules |
| [`kubernetes`](examples/kubernetes/app.yaml) | A cert-manager `Certificate` mounted into a Deployment |
| [`grpccreds`](grpccreds/example_test.go) | gRPC server and client with mutual TLS |

There are also runnable snippets in [`example_test.go`](example_test.go), which appear on pkg.go.dev.

## Using it

| You have | Use | Verification |
|---|---|---|
| Any `crypto/tls` server (`http.Server`, raw listeners) | `r.ServerConfig(base)` | crypto/tls |
| An `http.Transport` or your own TLS dials | `r.ConfigureTransport(tr, base)` or `r.DialTLSContext(base)` | crypto/tls |
| grpc-go | `grpccreds.New(r)` from `github.com/rossedman/keyload/grpccreds` | crypto/tls |
| A library that only accepts a `*tls.Config` | `r.ClientConfig(base)` ("Config mode") | keyload, matching crypto/tls |

`base` is an optional `*tls.Config` with your other settings (`ClientAuth`, `MinVersion`, `ServerName`, ...). keyload fills in the certificates and CAs from the current files.

```go
creds := grpccreds.New(r, grpccreds.WithTLSConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}))
srv := grpc.NewServer(grpc.Creds(creds))
conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(grpccreds.New(r)))
```

## Files

| Field | Description |
|---|---|
| `Cert` | Your certificate, optionally followed by intermediates. Leave empty for a client that only verifies servers. |
| `Key` | The private key for `Cert`. Set together with `Cert`. |
| `Roots` | CA bundle for verifying servers (client side). Empty means the system roots. |
| `ClientCAs` | CA bundle for verifying clients (server side). |

keyload watches the files' directories with inotify, so a Kubernetes Secret update is seen within moments. Mount the whole Secret as a directory: a `subPath` mount never sees updates. On NFS, FUSE and other filesystems where inotify misses changes, or on macOS and Windows, it checks every 30 seconds instead.

Other sources (Vault, a secrets API) implement `Source` and return PEM. `keyload.SourceFunc` turns a function into one.

## What gets rejected

Every reload is validated before it's used. If any check fails, the current certificates stay in service, an `Event` with the reason is sent to `OnReload`, and `keyload_reload_total{result="invalid"}` goes up.

| Check | Error |
|---|---|
| The key matches the certificate | `ErrKeyMismatch` |
| Every certificate in the chain is inside its validity window | `ErrExpired`, `ErrNotYetValid` |
| At least `MinRemaining(d)` is left before the chain expires | `ErrExpiresTooSoon` |
| The certificate chains to the new roots (with `RequireChain()`) | `ErrChainVerification` |
| Each CA bundle has at least one certificate | `ErrEmptyBundle` |
| No truncated PEM | `ErrTruncatedPEM` |

Files that look half-written (a new certificate next to the old key, a truncated bundle) are retried 3 times with a short backoff first, so a certificate manager that writes files one by one doesn't cause false alarms.

## Options

```go
r, err := keyload.New(files,
	keyload.MinRemaining(time.Hour),        // reject certificates that expire within the hour
	keyload.RequireChain(),                 // reject a certificate that doesn't chain to the new roots
	keyload.OverlapWindow(24*time.Hour),    // keep removed CAs trusted for a day
	keyload.OnSignal(syscall.SIGHUP),       // reload on SIGHUP
	keyload.PollEvery(5*time.Minute),       // and on a timer
	keyload.OnReload(func(keyload.Event) {}),
	keyload.Name("api"),                    // label metrics when running several reloaders
)
```

**Rotating a CA.** With `OverlapWindow`, a CA that's removed from a bundle stays trusted for that long after it's removed. Add the new CA, move certificates over, remove the old CA: peers that haven't rotated yet keep working until the window ends, and then the old CA is dropped automatically.

## Observability

`keyload.MetricsHandler(r)` serves Prometheus text format without a client library. `r.Stats()` returns the same numbers for other systems.

| Metric | Meaning |
|---|---|
| `keyload_generation` | Current snapshot generation |
| `keyload_reload_total{result}` | Reloads by result: `success`, `invalid`, `read_error` |
| `keyload_cert_not_after_seconds{role}` | Expiry of your certificate chain and of the earliest CA in each bundle (`leaf`, `roots`, `client_cas`) |
| `keyload_last_success_timestamp_seconds` | Time of the last successful reload |

```yaml
- alert: CertificateExpiresSoon
  expr: keyload_cert_not_after_seconds - time() < 7 * 86400
- alert: CertificateReloadFailing
  expr: increase(keyload_reload_total{result!="success"}[15m]) > 0
```

Events name the file and the reason for a rejection, and the subjects and serials that changed on success. They never include key material.

## Testing your code

Write the files to `t.TempDir()` and call `r.Reload(ctx)` to apply a change at once, instead of waiting for the file watcher:

```go
ca.issue(t, dir, time.Now().Add(24*time.Hour)) // write a new tls.crt and tls.key
if err := r.Reload(context.Background()); err != nil {
	t.Fatal(err)
}
// the next connection uses the new certificate
```

[`examples/quickstart/keyload_test.go`](examples/quickstart/keyload_test.go) is a complete test, and [`certs_test.go`](examples/quickstart/certs_test.go) generates the certificates with `crypto/x509` only, so you can copy it into your project.

## Good to know

- **HTTP/2 servers.** Set `NextProtos: []string{"h2", "http/1.1"}` in the base config you pass to `ServerConfig`. `http.Server` adds `h2` to a copy of its config, which keyload doesn't see.
- **HTTPS proxies.** `http.Transport` skips `DialTLSContext` for proxied HTTPS, so `ConfigureTransport` returns `ErrProxyConfigured`. Use `ClientConfig` there (see the [`proxy`](examples/proxy/main.go) example).
- **Config mode** sets `InsecureSkipVerify` and verifies in `VerifyConnection` with the same options crypto/tls uses, on every handshake including resumed ones. It requires `ServerName`. `ConnectionState.VerifiedChains` is empty in this mode. It's tested against crypto/tls on thousands of generated chains; see [SECURITY.md](SECURITY.md).
- **Session resumption** keeps working across reloads on servers. A resumed session's client certificate is re-checked against the current client CAs, so removing a CA also stops its clients from resuming.
- **Existing connections** keep the certificates they were established with. Only new handshakes use reloaded material.

## Performance

The handshake path takes no locks and makes no allocations: `ServerConfig` hands each handshake a config cached per reload. Representative numbers from `go test -bench . -benchmem` on a 4-vCPU Xeon VM:

| Operation | Time | Allocs |
|---|---|---|
| Server handshake overhead (cached config) | ~2.5 ns | 0 |
| First handshake after a reload (builds the config) | ~430 ns | 5 |
| Client connection overhead (`DialTLSContext`) | ~260 ns | 2 |
| Config mode verification vs. crypto/tls's own | ~177 µs vs. ~180 µs | same |
| Reload of unchanged files | ~2.4 µs | 3 |

CI runs the benchmarks on each push and pull request, and `TestHotPathAllocations` fails the build if the handshake path starts allocating.

## Testing

Besides unit tests, CI runs:

- **Rotation under load**: certificates and CAs rotated on both sides mid-traffic over HTTP/1.1, HTTP/2 and gRPC, with zero failed requests allowed.
- **Bad-reload drills**: every kind of bad file must keep the old certificates and report the right reason.
- **Kubernetes Secret volumes**: the kubelet's `..data` symlink swap, on a real filesystem.
- **Differential verification**: 2,000 generated chains (wrong host, IP SANs, expired intermediates, wrong key usage, name constraints) checked by crypto/tls and by Config mode. Any disagreement fails the build.
- **Fuzzing** of the PEM parsing and validation.

## License

[MIT](LICENSE)
