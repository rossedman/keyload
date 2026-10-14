# client

An HTTPS client with mutual TLS that calls a URL on an interval. The certificate it presents, and the CA bundle it trusts, reload from disk while it runs. Every new connection uses the current files.

## Run it

Start the [server](../server) first, then the client:

```sh
go run ./examples/gencerts -dir /tmp/keyload
go run ./examples/server -dir /tmp/keyload &
go run ./examples/client -dir /tmp/keyload -url https://localhost:8443/

go run ./examples/gencerts -dir /tmp/keyload -rotate   # both sides reload
```

Without a clone, use `go run github.com/rossedman/keyload/examples/<name>@latest` instead of `go run ./examples/<name>`.

| Flag | Default | |
|---|---|---|
| `-dir` | `keyload-certs` | Directory with `tls.crt`, `tls.key` and `ca.crt`. |
| `-url` | `https://localhost:8443/` | URL to request. |
| `-interval` | `2s` | Time between requests. |

## What you'll see

```
HTTP/2.0 200 OK: hello, localhost
HTTP/2.0 200 OK: hello, localhost
```

Requests keep succeeding across the rotation. The client keeps its HTTP/2 connection open, and an open connection keeps the certificates it started with; new connections use the new files.

Pointed at a server whose certificate comes from a CA it doesn't trust, it reports:

```
error: Get "https://localhost:8444/": tls: failed to verify certificate: x509: certificate signed by unknown authority
```

Add that CA to `ca.crt` and the next connection succeeds, without a restart.

## How it works

```go
r, err := keyload.New(keyload.Files{
	Cert:  filepath.Join(dir, "tls.crt"),
	Key:   filepath.Join(dir, "tls.key"),
	Roots: filepath.Join(dir, "ca.crt"),
})

tr := &http.Transport{ForceAttemptHTTP2: true}
if err := r.ConfigureTransport(tr, nil); err != nil {
	return err // keyload.ErrProxyConfigured if tr would use an HTTPS proxy
}
client := &http.Client{Transport: tr}
```

`ConfigureTransport` sets the transport's `DialTLSContext`, which builds a fresh `tls.Config` from the current files for every connection. crypto/tls verifies the server. When the transport sends HTTPS through a proxy it never calls `DialTLSContext`, so `ConfigureTransport` refuses; see the [proxy](../proxy) example.

## Test

```sh
go test ./examples/client
```

Source: [`main.go`](main.go)
