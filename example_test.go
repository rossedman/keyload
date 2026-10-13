package keyload_test

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"syscall"
	"time"

	"github.com/rossedman/keyload"
)

// A mutual-TLS HTTP server and client fed from a Kubernetes Secret volume.
func Example() {
	ctx := context.Background()
	r, err := keyload.New(ctx, keyload.FromFiles(keyload.Files{
		Cert: "/tls/tls.crt", Key: "/tls/tls.key",
		Roots: "/tls/ca.crt", ClientCAs: "/tls/ca.crt",
	}),
		keyload.MinRemaining(time.Hour),
		keyload.OverlapWindow(24*time.Hour),
		keyload.OnSignal(syscall.SIGHUP),
		keyload.OnReload(func(ev keyload.Event) {
			if ev.Err != nil {
				log.Printf("TLS reload rejected, still serving generation %d: %v", ev.Generation, ev.Err)
			}
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	srv := &http.Server{
		Addr: ":8443",
		TLSConfig: r.ServerConfig(&tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			NextProtos: []string{"h2", "http/1.1"},
		}),
	}
	go srv.ListenAndServeTLS("", "")

	tr := &http.Transport{ForceAttemptHTTP2: true}
	if err := r.ConfigureTransport(tr, &tls.Config{}); err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Transport: tr}
	_ = client

	http.Handle("/metrics", keyload.MetricsHandler(r))
}

// Config mode, for a library that only accepts a *tls.Config.
func ExampleReloader_ClientConfig() {
	r, err := keyload.New(context.Background(), keyload.FromFiles(keyload.Files{Roots: "/tls/ca.crt"}))
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := r.ClientConfig(&tls.Config{ServerName: "db.internal"})
	if err != nil {
		log.Fatal(err)
	}
	_ = cfg // pass to the library
}
