// Command metrics serves Prometheus metrics for a reloader and logs every
// reload as structured JSON. Alert on keyload_cert_not_after_seconds to catch
// a certificate that stopped renewing, and on keyload_reload_total
// {result!="success"} to catch bad files being pushed.
//
//	go run ./examples/gencerts -dir /tmp/keyload
//	go run ./examples/metrics -dir /tmp/keyload
//
//	curl localhost:9090/metrics
//	echo oops > /tmp/keyload/tls.key && curl -s localhost:9090/metrics | grep reload_total
//
// Example alerting rules:
//
//	rules:
//	  - alert: CertificateExpiresSoon
//	    expr: keyload_cert_not_after_seconds - time() < 7 * 86400
//	  - alert: CertificateReloadFailing
//	    expr: increase(keyload_reload_total{result!="success"}[15m]) > 0
package main

import (
	"context"
	"errors"
	"flag"
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

// run serves metrics on ln for TLS material in dir until ctx is canceled.
func run(ctx context.Context, ln net.Listener, dir string, logger *slog.Logger) error {
	r, err := keyload.New(keyload.Files{
		Cert:  filepath.Join(dir, "tls.crt"),
		Key:   filepath.Join(dir, "tls.key"),
		Roots: filepath.Join(dir, "ca.crt"),
	},
		keyload.Name("api"),
		keyload.OnReload(func(ev keyload.Event) {
			attrs := []any{"generation", ev.Generation, "trigger", ev.Trigger, "result", ev.Result}
			if len(ev.Added) > 0 {
				attrs = append(attrs, "added", certList(ev.Added))
			}
			if len(ev.Removed) > 0 {
				attrs = append(attrs, "removed", certList(ev.Removed))
			}
			if ev.Err != nil {
				logger.Error("tls reload rejected", append(attrs, "err", ev.Err)...)
				return
			}
			logger.Info("tls reload", attrs...)
		}),
	)
	if err != nil {
		return err
	}
	defer r.Close()

	mux := http.NewServeMux()
	mux.Handle("/metrics", keyload.MetricsHandler(r))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

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

// certList turns certificates from an event into a list for the log, so
// several certificates don't repeat the same JSON key.
func certList(infos []keyload.CertInfo) []map[string]any {
	out := make([]map[string]any, len(infos))
	for i, c := range infos {
		out[i] = map[string]any{"role": c.Role, "subject": c.Subject, "serial": c.Serial, "not_after": c.NotAfter}
	}
	return out
}

// cli parses args and serves /metrics until ctx is done.
func cli(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("metrics", flag.ContinueOnError)
	addr := fs.String("addr", ":9090", "address for /metrics")
	dir := fs.String("dir", "keyload-certs", "directory with tls.crt, tls.key and ca.crt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	return run(ctx, ln, *dir, slog.New(slog.NewJSONHandler(os.Stderr, nil)))
}

// main runs the metrics server until it is interrupted.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := cli(ctx, os.Args[1:])
	stop()
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
