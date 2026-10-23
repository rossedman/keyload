// Command quickstart is the README's quick start as a program: an HTTPS
// server with mutual TLS, and a client calling it once a second, both using
// one keyload Reloader. Rotate or break the files while it runs to watch
// keyload at work. No clone needed:
//
//	go run github.com/rossedman/keyload/examples/gencerts@latest -dir ./certs
//	go run github.com/rossedman/keyload/examples/quickstart@latest -dir ./certs
//
//	# in another terminal
//	go run github.com/rossedman/keyload/examples/gencerts@latest -dir ./certs -rotate
//	echo oops > ./certs/tls.key       # rejected; the last good certificate keeps serving
//	go run github.com/rossedman/keyload/examples/gencerts@latest -dir ./certs -rotate
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rossedman/keyload"
)

// run serves on ln and requests from it every interval, until ctx is
// canceled.
func run(ctx context.Context, ln net.Listener, dir string, interval time.Duration, logger *log.Logger) error {
	r, err := keyload.New(keyload.Files{
		Cert:      filepath.Join(dir, "tls.crt"),
		Key:       filepath.Join(dir, "tls.key"),
		Roots:     filepath.Join(dir, "ca.crt"), // CAs to verify servers
		ClientCAs: filepath.Join(dir, "ca.crt"), // CAs to verify clients
	}, keyload.OnReload(func(ev keyload.Event) {
		if ev.Err != nil {
			logger.Printf("TLS reload rejected, still serving generation %d: %v", ev.Generation, ev.Err)
			return
		}
		logger.Printf("TLS reload: generation %d (%s)", ev.Generation, ev.Trigger)
	}))
	if err != nil {
		return err // the first load must be valid
	}
	defer r.Close()

	// Server: the certificate and client CAs follow reloads.
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			fmt.Fprintf(w, "hello %s", html.EscapeString(req.TLS.PeerCertificates[0].Subject.CommonName))
		}),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: r.ServerConfig(&tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAndVerifyClientCert,
			NextProtos: []string{"h2", "http/1.1"}, // HTTP/2
		}),
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }() // "" "": the certificate comes from TLSConfig
	defer srv.Close()

	// Client: every connection uses the current certificate and roots.
	tr := &http.Transport{ForceAttemptHTTP2: true}
	if err := r.ConfigureTransport(tr, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "localhost"}); err != nil {
		return err
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	url := "https://" + ln.Addr().String() + "/"

	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		resp, err := client.Get(url)
		if err != nil {
			logger.Printf("request failed: %v", err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		logger.Printf("%s over %s; server certificate serial %X", body, resp.Proto, resp.TLS.PeerCertificates[0].SerialNumber)
		tr.CloseIdleConnections() // a new connection each time, so rotations show up
	}
}

// cli parses args and runs the quickstart until ctx is done.
func cli(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("quickstart", flag.ContinueOnError)
	dir := fs.String("dir", "certs", "directory with tls.crt, tls.key and ca.crt")
	addr := fs.String("addr", "127.0.0.1:8443", "address to listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return run(ctx, ln, *dir, time.Second, log.New(os.Stderr, "", log.LstdFlags))
}

// main runs the quickstart until it is interrupted.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := cli(ctx, os.Args[1:])
	stop()
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}
