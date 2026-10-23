// Command client calls an HTTPS URL on an interval, presenting a client
// certificate and trusting a CA bundle that both reload from disk. Every new
// connection uses the current files, so a rotated CA or certificate takes
// effect without restarting the client.
//
//	go run ./examples/gencerts -dir /tmp/keyload
//	go run ./examples/server -dir /tmp/keyload &
//	go run ./examples/client -dir /tmp/keyload -url https://localhost:8443/
//
//	go run ./examples/gencerts -dir /tmp/keyload -rotate   # both sides reload
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rossedman/keyload"
)

// run requests url every interval until ctx is canceled, writing one line
// per request to out.
func run(ctx context.Context, url, dir string, interval time.Duration, out io.Writer) error {
	r, err := keyload.New(keyload.Files{
		Cert:  filepath.Join(dir, "tls.crt"),
		Key:   filepath.Join(dir, "tls.key"),
		Roots: filepath.Join(dir, "ca.crt"),
	})
	if err != nil {
		return err
	}
	defer r.Close()

	tr := &http.Transport{ForceAttemptHTTP2: true}
	if err := r.ConfigureTransport(tr, nil); err != nil {
		return err
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if err := get(ctx, client, url, out); err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// get requests url and copies the response body to out.
func get(ctx context.Context, client *http.Client, url string, out io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	fmt.Fprintf(out, "%s %s: %s\n", resp.Proto, resp.Status, strings.TrimSpace(string(body)))
	return nil
}

// cli parses args and requests the URL every interval until ctx is done.
func cli(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	url := fs.String("url", "https://localhost:8443/", "URL to request")
	dir := fs.String("dir", "keyload-certs", "directory with tls.crt, tls.key and ca.crt")
	interval := fs.Duration("interval", 2*time.Second, "time between requests")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return run(ctx, *url, *dir, *interval, os.Stdout)
}

// main runs the client until it is interrupted.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := cli(ctx, os.Args[1:])
	stop()
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
