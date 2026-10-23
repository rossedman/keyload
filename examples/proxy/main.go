// Command proxy calls an HTTPS URL through an HTTP proxy, trusting a CA
// bundle that reloads from disk.
//
// This is the case for Config mode. When http.Transport sends HTTPS through
// a proxy it does its own TLS with TLSClientConfig and never calls
// DialTLSContext, so ConfigureTransport refuses it. Reloader.ClientConfig
// returns a config that checks the server against the current CA bundle on
// every handshake instead. It needs ServerName, so it suits clients that talk
// to one host.
//
//	go run ./examples/proxy -url https://api.internal/ -proxy http://proxy:3128 -ca /tmp/keyload/ca.crt
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rossedman/keyload"
)

// newClient returns an HTTP client that reaches target's host through proxy
// and verifies it against the CA bundle at caFile, following reloads.
func newClient(target, proxy, caFile string) (*http.Client, *keyload.Reloader, error) {
	t, err := url.Parse(target)
	if err != nil {
		return nil, nil, err
	}
	p, err := url.Parse(proxy)
	if err != nil {
		return nil, nil, err
	}
	r, err := keyload.New(keyload.Files{Roots: caFile})
	if err != nil {
		return nil, nil, err
	}
	cfg, err := r.ClientConfig(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: t.Hostname()})
	if err != nil {
		_ = r.Close()
		return nil, nil, err
	}
	tr := &http.Transport{Proxy: http.ProxyURL(p), TLSClientConfig: cfg, ForceAttemptHTTP2: true}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}, r, nil
}

// run requests target through proxy, verifying the server with the CA
// bundle in caFile, and copies the response body to out.
func run(ctx context.Context, target, proxy, caFile string, out io.Writer) error {
	client, r, err := newClient(target, proxy, caFile)
	if err != nil {
		return err
	}
	defer r.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

// cli parses args and makes one request through the proxy.
func cli(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	target := fs.String("url", "", "HTTPS URL to request")
	proxy := fs.String("proxy", os.Getenv("HTTPS_PROXY"), "HTTP proxy URL")
	ca := fs.String("ca", "ca.crt", "CA bundle to verify the server with")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" || *proxy == "" {
		return errors.New("-url and -proxy are required")
	}
	return run(ctx, *target, *proxy, *ca, os.Stdout)
}

// main runs one request and exits non-zero if it fails.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := cli(ctx, os.Args[1:])
	stop()
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
