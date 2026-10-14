# quickstart

The [README's quick start](../../README.md#quick-start) as a program: an HTTPS server with mutual TLS, and a client that calls it once a second, both using one keyload `Reloader`. Rotate or break the certificate while it runs to watch keyload at work. Its tests show how to test your own code that uses keyload.

The [getting started guide](../../docs/getting-started.md) walks through the same program step by step.

## Run it

```sh
go run ./examples/gencerts -dir ./certs
go run ./examples/quickstart -dir ./certs
```

In another terminal:

```sh
go run ./examples/gencerts -dir ./certs -rotate
echo oops > ./certs/tls.key                      # rejected; the last good certificate keeps serving
go run ./examples/gencerts -dir ./certs -rotate  # back to a good certificate
```

Without a clone, use `go run github.com/rossedman/keyload/examples/<name>@latest` instead of `go run ./examples/<name>`. `quickstart` is available that way from the release after v0.1.0.

| Flag | Default | |
|---|---|---|
| `-dir` | `certs` | Directory with `tls.crt`, `tls.key` and `ca.crt`. |
| `-addr` | `127.0.0.1:8443` | Address to listen on. |

## What you'll see

Timestamps trimmed:

```
TLS reload: generation 1 (initial)
hello localhost over HTTP/2.0; server certificate serial 2F44015CCD05742B
TLS reload: generation 2 (watch)
hello localhost over HTTP/2.0; server certificate serial 1343900835CDD9D7
TLS reload rejected, still serving generation 2: keyload: invalid material (key certs/tls.key): truncated or malformed PEM block
hello localhost over HTTP/2.0; server certificate serial 1343900835CDD9D7
TLS reload: generation 3 (watch)
hello localhost over HTTP/2.0; server certificate serial 3EF7582068B7B062
```

The serial number changes on the next request after a rotation, with no restart. The broken key is rejected, and the previous certificate keeps serving until a good one arrives.

## How it works

One `Reloader` feeds both sides:

```go
r, err := keyload.New(keyload.Files{
	Cert:      filepath.Join(dir, "tls.crt"),
	Key:       filepath.Join(dir, "tls.key"),
	Roots:     filepath.Join(dir, "ca.crt"), // CAs to verify servers
	ClientCAs: filepath.Join(dir, "ca.crt"), // CAs to verify clients
})

srv := &http.Server{TLSConfig: r.ServerConfig(&tls.Config{
	ClientAuth: tls.RequireAndVerifyClientCert,
	NextProtos: []string{"h2", "http/1.1"},
})}
go srv.ServeTLS(ln, "", "") // no file names: the certificate comes from TLSConfig

tr := &http.Transport{ForceAttemptHTTP2: true}
err = r.ConfigureTransport(tr, &tls.Config{ServerName: "localhost"})
```

The client closes idle connections after each request so every request makes a new connection and picks up rotations. A real client doesn't need that: its open connections keep their certificates, and new ones use the current files.

## Testing your own code

The tests are written the way you would write them in your own project:

- [`certs_test.go`](certs_test.go) generates a CA and certificates with `crypto/x509` only. Copy it as a starting point.
- [`keyload_test.go`](keyload_test.go) writes files to `t.TempDir()` and calls `r.Reload(ctx)` to apply a change at once, instead of waiting for the file watcher. It checks rotation over HTTP/2, a rejected key, `MinRemaining`, and `ErrProxyConfigured`.
- [`main_test.go`](main_test.go) runs the program and checks its output through a rotation, a broken key and a fix.

```sh
go test ./examples/quickstart
```

Source: [`main.go`](main.go)
