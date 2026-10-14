# Getting started

This walks through using keyload in a new project: install it, get some
certificates, run a server and client with mutual TLS, rotate and break the
certificates while they run, and test your own code. Every step here was run
as written; the program and its tests are in
[`examples/quickstart`](../examples/quickstart).

You need Go 1.24 or newer.

## 1. Install

```sh
mkdir myapp && cd myapp
go mod init example.com/myapp
go get github.com/rossedman/keyload
```

The core module has no dependencies outside the standard library. For grpc-go,
also `go get github.com/rossedman/keyload/grpccreds`.

## 2. Get certificates

keyload reads PEM files: a certificate (`tls.crt`), its key (`tls.key`) and a
CA bundle (`ca.crt`). In production these come from cert-manager, Vault or
your own CA. To try things out, `gencerts` writes a throwaway CA and a
certificate for `localhost`, laid out like a cert-manager Secret:

```sh
go run github.com/rossedman/keyload/examples/gencerts@latest -dir ./certs
```

<details>
<summary>Or with openssl</summary>

```sh
mkdir certs && cd certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -keyout ca.key -out ca.crt -subj "/CN=Demo CA"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout tls.key -out tls.csr -subj "/CN=localhost"
printf 'subjectAltName = DNS:localhost, IP:127.0.0.1\nextendedKeyUsage = serverAuth, clientAuth\n' > ext.cnf
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 \
  -extfile ext.cnf -out tls.crt
cd ..
```

Run the last three commands again to rotate the certificate. Write to new
files and `mv` them into place, as certificate managers do, so keyload never
sees a half-written file.

</details>

## 3. Use it

`main.go`: an HTTPS server that requires client certificates, and a client
that calls it every second. Both get their certificate and CAs from one
`Reloader`.

```go
package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/rossedman/keyload"
)

func main() {
	r, err := keyload.New(keyload.Files{
		Cert:      "certs/tls.crt",
		Key:       "certs/tls.key",
		Roots:     "certs/ca.crt", // CAs to verify servers
		ClientCAs: "certs/ca.crt", // CAs to verify clients
	}, keyload.OnReload(func(ev keyload.Event) {
		if ev.Err != nil {
			log.Printf("TLS reload rejected, still serving generation %d: %v", ev.Generation, ev.Err)
			return
		}
		log.Printf("TLS reload: generation %d (%s)", ev.Generation, ev.Trigger)
	}))
	if err != nil {
		log.Fatal(err) // the first load must be valid
	}
	defer r.Close()

	srv := &http.Server{
		Addr: "127.0.0.1:8443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			io.WriteString(w, "hello "+req.TLS.PeerCertificates[0].Subject.CommonName)
		}),
		TLSConfig: r.ServerConfig(&tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			NextProtos: []string{"h2", "http/1.1"}, // for HTTP/2, set this here
		}),
	}
	// Empty file names: the certificate comes from TLSConfig.
	go func() { log.Fatal(srv.ListenAndServeTLS("", "")) }()

	tr := &http.Transport{ForceAttemptHTTP2: true}
	if err := r.ConfigureTransport(tr, nil); err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Transport: tr}

	for range time.Tick(time.Second) {
		resp, err := client.Get("https://localhost:8443/")
		if err != nil {
			log.Printf("request failed: %v", err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		log.Printf("%s over %s; server certificate serial %X", body, resp.Proto, resp.TLS.PeerCertificates[0].SerialNumber)
		tr.CloseIdleConnections() // a new connection each time, so rotations show up
	}
}
```

```sh
go mod tidy
go run .
```

```
2026/10/14 12:59:51 TLS reload: generation 1 (initial)
2026/10/14 12:59:52 hello localhost over HTTP/2.0; server certificate serial 2F44015CCD05742B
2026/10/14 12:59:53 hello localhost over HTTP/2.0; server certificate serial 2F44015CCD05742B
```

`tr.CloseIdleConnections()` is only there so this demo opens a new connection
every second. A real client keeps its connections; new ones pick up the new
certificates, and existing ones keep the certificates they started with.

## 4. Rotate and break things

In another terminal, rotate the certificate:

```sh
go run github.com/rossedman/keyload/examples/gencerts@latest -dir ./certs -rotate
```

```
2026/10/14 12:59:53 TLS reload: generation 2 (watch)
2026/10/14 12:59:54 hello localhost over HTTP/2.0; server certificate serial 1343900835CDD9D7
```

The next connection uses the new certificate, with no restart. Now write a
broken key:

```sh
echo oops > certs/tls.key
```

```
2026/10/14 12:59:56 TLS reload rejected, still serving generation 2: keyload: invalid material (key certs/tls.key): truncated or malformed PEM block
2026/10/14 12:59:57 hello localhost over HTTP/2.0; server certificate serial 1343900835CDD9D7
```

keyload rejects it and keeps serving the last good certificate. Rotating
again fixes it:

```
2026/10/14 12:59:57 TLS reload: generation 3 (watch)
2026/10/14 12:59:58 hello localhost over HTTP/2.0; server certificate serial 3EF7582068B7B062
```

Things that are rejected the same way: an expired or not-yet-valid
certificate, a certificate expiring sooner than `MinRemaining`, an empty CA
bundle, and a certificate that doesn't chain to the new roots (with
`RequireChain`). Files caught mid-write, such as a new certificate next to the
old key, are retried for a moment first, so a certificate manager that writes
one file at a time doesn't cause false alarms.

## 5. Test your code

In tests, write the files to `t.TempDir()` and call `r.Reload(ctx)` to apply a
change at once instead of waiting for the file watcher:

```go
func TestRotation(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)                                  // writes ca.crt
	first := ca.issue(t, dir, time.Now().Add(24*time.Hour)) // writes tls.crt and tls.key

	r, err := keyload.New(files(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// ... serve with r.ServerConfig, connect with r.ConfigureTransport ...

	second := ca.issue(t, dir, time.Now().Add(24*time.Hour))
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	// ... the next connection sees second ...
}
```

[`examples/quickstart/keyload_test.go`](../examples/quickstart/keyload_test.go)
has the full test, and
[`certs_test.go`](../examples/quickstart/certs_test.go) has `newCA` and
`issue`, written with `crypto/x509` only so you can copy them into your
project.

## 6. Before production

- **Kubernetes:** mount the Secret as a whole directory. A `subPath` mount
  never sees updates. See [`examples/kubernetes`](../examples/kubernetes/app.yaml).
- **Alerting:** serve `keyload.MetricsHandler(r)` and alert on
  `keyload_cert_not_after_seconds` and `keyload_reload_total{result!="success"}`.
  See [`examples/metrics`](../examples/metrics/main.go).
- **Short-lived certificates:** `keyload.MinRemaining(time.Hour)` refuses a
  certificate that's about to expire.
- **CA rotation:** `keyload.OverlapWindow(24*time.Hour)` keeps a removed CA
  trusted for a day, so peers have time to rotate.
- **HTTPS proxies:** `ConfigureTransport` returns `ErrProxyConfigured` when
  the transport would use one, because `http.Transport` skips the custom
  dialer for proxied requests. Use `r.ClientConfig` there; see
  [`examples/proxy`](../examples/proxy/main.go).
- **gRPC:** `grpccreds.New(r)` from `github.com/rossedman/keyload/grpccreds`.
