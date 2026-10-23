// Command server is an HTTPS server with mutual TLS. Its certificate and the
// CA bundle it checks clients against reload from disk while it runs: no
// restart when cert-manager (or anything else) renews them.
//
//	go run ./examples/gencerts -dir /tmp/keyload
//	go run ./examples/server -dir /tmp/keyload
//
//	curl --cacert /tmp/keyload/ca.crt --cert /tmp/keyload/tls.crt \
//	     --key /tmp/keyload/tls.key https://localhost:8443/
//
//	go run ./examples/gencerts -dir /tmp/keyload -rotate   # the server logs the reload
//	echo oops > /tmp/keyload/tls.key                       # rejected; it keeps serving
//	kill -HUP $(pgrep server)                              # reload on demand
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rossedman/keyload"
)

// run serves on ln with TLS material from dir until ctx is canceled.
func run(ctx context.Context, ln net.Listener, dir string, logger *slog.Logger) error {
	r, err := keyload.New(keyload.Files{
		Cert:      filepath.Join(dir, "tls.crt"),
		Key:       filepath.Join(dir, "tls.key"),
		ClientCAs: filepath.Join(dir, "ca.crt"),
	},
		keyload.OnSignal(syscall.SIGHUP),
		keyload.OnReload(func(ev keyload.Event) {
			if ev.Err != nil {
				logger.Error("TLS reload rejected; still serving the previous certificate",
					"generation", ev.Generation, "trigger", ev.Trigger, "err", ev.Err)
				return
			}
			logger.Info("TLS material loaded", "generation", ev.Generation, "trigger", ev.Trigger,
				"expires", leafExpiry(ev.Added))
		}),
	)
	if err != nil {
		return err
	}
	defer r.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			fmt.Fprintf(w, "hello, %s\n", html.EscapeString(req.TLS.PeerCertificates[0].Subject.CommonName))
		}),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: r.ServerConfig(&tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAndVerifyClientCert,
			NextProtos: []string{"h2", "http/1.1"},
		}),
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeTLS(ln, "", "") }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	if serr := <-serveErr; err == nil && !errors.Is(serr, http.ErrServerClosed) {
		err = serr
	}
	return err
}

// leafExpiry returns the expiry of the leaf among added certificates, if any.
func leafExpiry(added []keyload.CertInfo) string {
	for _, c := range added {
		if c.Role == keyload.RoleLeaf {
			return c.NotAfter.Format(time.RFC3339)
		}
	}
	return "unchanged"
}

// cli parses args and serves HTTPS until ctx is done.
func cli(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	addr := fs.String("addr", ":8443", "address to listen on")
	dir := fs.String("dir", "keyload-certs", "directory with tls.crt, tls.key and ca.crt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	logger.Info("listening", "addr", ln.Addr().String(), "dir", *dir)
	return run(ctx, ln, *dir, logger)
}

// main runs the server until it is interrupted.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := cli(ctx, os.Args[1:])
	stop()
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
