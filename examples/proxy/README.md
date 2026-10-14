# proxy

An HTTPS client that goes through an HTTP proxy and trusts a CA bundle that reloads from disk. It shows Config mode (`Reloader.ClientConfig`), keyload's option for when the dialer-based integration can't be used.

When `http.Transport` sends HTTPS through a proxy, it does the TLS handshake itself with `TLSClientConfig` and never calls `DialTLSContext`. So `ConfigureTransport` returns `keyload.ErrProxyConfigured`, and you use `ClientConfig` instead.

## Run it

You need an HTTP proxy and an HTTPS server whose certificate comes from your CA:

```sh
go run ./examples/proxy -url https://api.internal/ -proxy http://proxy:3128 -ca /tmp/keyload/ca.crt
```

Without a clone, use `go run github.com/rossedman/keyload/examples/<name>@latest` instead of `go run ./examples/<name>`.

| Flag | Default | |
|---|---|---|
| `-url` | | HTTPS URL to request. Required. |
| `-proxy` | `$HTTPS_PROXY` | HTTP proxy URL. Required. |
| `-ca` | `ca.crt` | CA bundle to verify the server with. |

## What you'll see

The response body, fetched through the proxy:

```
hello from the backend
```

With a CA bundle that didn't sign the server's certificate:

```
Get "https://localhost:8445/": tls: failed to verify certificate: x509: certificate signed by unknown authority
```

## How it works

```go
r, err := keyload.New(keyload.Files{Roots: caFile})

cfg, err := r.ClientConfig(&tls.Config{ServerName: "api.internal"})

tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: cfg}
```

- `ClientConfig` sets `InsecureSkipVerify` and checks the server in `VerifyConnection` against the current CA bundle, on every handshake including resumed ones, with the same options crypto/tls uses. CI compares it with crypto/tls on 2,000 generated certificate chains.
- `ServerName` is required: it's the hostname the server's certificate is checked against. Config mode therefore suits a client that talks to one host.
- `ConnectionState.VerifiedChains` is empty in this mode, because crypto/tls didn't verify.

Prefer [`ConfigureTransport`](../client) whenever no proxy is involved.

## Test

```sh
go test ./examples/proxy
```

The test runs a CONNECT proxy and an HTTPS backend, reloads the CA bundle, and checks that requests go through the proxy.

Source: [`main.go`](main.go)
