# server

An HTTPS server with mutual TLS. Its certificate, and the CA bundle it checks client certificates against, reload from disk while it runs: no restart when cert-manager (or anything else) renews them. `SIGHUP` forces a reload.

## Run it

```sh
go run ./examples/gencerts -dir /tmp/keyload
go run ./examples/server -dir /tmp/keyload
```

Without a clone, use `go run github.com/rossedman/keyload/examples/<name>@latest` instead of `go run ./examples/<name>`.

In another terminal:

```sh
curl --cacert /tmp/keyload/ca.crt --cert /tmp/keyload/tls.crt \
     --key /tmp/keyload/tls.key https://localhost:8443/

go run ./examples/gencerts -dir /tmp/keyload -rotate   # the server logs the reload
echo oops > /tmp/keyload/tls.key                       # rejected; it keeps serving
kill -HUP $(pgrep -x server)                           # reload on demand
go run ./examples/gencerts -dir /tmp/keyload -rotate   # back to a good certificate
```

| Flag | Default | |
|---|---|---|
| `-dir` | `keyload-certs` | Directory with `tls.crt`, `tls.key` and `ca.crt`. |
| `-addr` | `:8443` | Address to listen on. |

## What you'll see

`curl` prints `hello, localhost`. The server logs each reload (timestamps trimmed):

```
level=INFO msg=listening addr=127.0.0.1:8443 dir=/tmp/keyload
level=INFO msg="TLS material loaded" generation=1 trigger=initial expires=2026-10-15T13:21:55Z
level=INFO msg="TLS material loaded" generation=2 trigger=watch expires=2026-10-15T13:21:56Z
level=ERROR msg="TLS reload rejected; still serving the previous certificate" generation=2 trigger=watch err="keyload: invalid material (key /tmp/keyload/tls.key): truncated or malformed PEM block"
level=ERROR msg="TLS reload rejected; still serving the previous certificate" generation=2 trigger=signal err="keyload: invalid material (key /tmp/keyload/tls.key): truncated or malformed PEM block"
level=INFO msg="TLS material loaded" generation=3 trigger=watch expires=2026-10-15T13:22:00Z
```

- `trigger=watch`: the file watcher saw the change.
- The broken key is rejected, and generation 2 keeps serving.
- `trigger=signal`: `SIGHUP` reloaded on demand. It reports the broken key again because the files on disk are still bad. A `SIGHUP` with unchanged, valid files does nothing and logs nothing.

## How it works

```go
r, err := keyload.New(keyload.Files{
	Cert:      filepath.Join(dir, "tls.crt"),
	Key:       filepath.Join(dir, "tls.key"),
	ClientCAs: filepath.Join(dir, "ca.crt"),
},
	keyload.OnSignal(syscall.SIGHUP),
	keyload.OnReload(func(ev keyload.Event) { /* log it */ }),
)

srv := &http.Server{
	TLSConfig: r.ServerConfig(&tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"h2", "http/1.1"},
	}),
}
srv.ServeTLS(ln, "", "") // no file names: the certificate comes from TLSConfig
```

- `ServerConfig` gives each handshake a config built from the current files. crypto/tls still does all certificate verification.
- Set `NextProtos` in the config you pass to `ServerConfig`, not on the server afterwards; that's what enables HTTP/2.
- If the first load fails, `keyload.New` returns an error and the server doesn't start with bad certificates.

## Test

```sh
go test ./examples/server
```

Source: [`main.go`](main.go)
