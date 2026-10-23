package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

// connectProxy is a minimal HTTP CONNECT proxy that counts tunnels.
func connectProxy(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var tunnels atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		tunnels.Add(1)
		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			conn.Close()
			upstream.Close()
			return
		}
		// rw.Reader may already hold bytes the client sent after CONNECT.
		go func() { _, _ = io.Copy(upstream, rw.Reader); upstream.Close() }()
		go func() { _, _ = io.Copy(conn, upstream); conn.Close() }()
	}))
	t.Cleanup(srv.Close)
	return srv, &tunnels
}

func TestThroughProxyWithReloadedRoots(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("waits for the file watcher, which polls every 30s off Linux")
	}
	dir := testpki.NewDir(t, t.TempDir())
	other := testpki.NewCA(t, "other")
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secret data")
	}))
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{other.Issue(t, testpki.LeafOptions{}).TLS(t)}}
	backend.StartTLS()
	defer backend.Close()
	target := "https://localhost:" + strings.Split(backend.Listener.Addr().String(), ":")[1] + "/"
	proxy, tunnels := connectProxy(t)

	client, r, err := newClient(target, proxy.URL, dir.File("ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if _, err := client.Get(target); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("untrusted backend: err = %v", err)
	}
	testpki.WriteFile(t, dir.File("ca.crt"), other.PEM())
	deadline := time.Now().Add(5 * time.Second)
	for {
		client.CloseIdleConnections()
		resp, err := client.Get(target)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) != "secret data" {
				t.Fatalf("body = %q", b)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still failing after CA reload: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if tunnels.Load() < 2 {
		t.Errorf("requests did not go through the proxy (%d tunnels)", tunnels.Load())
	}

	var out strings.Builder
	if err := run(context.Background(), target, proxy.URL, dir.File("ca.crt"), &out); err != nil || out.String() != "secret data" {
		t.Errorf("run() = %v, output %q", err, out.String())
	}
}

func TestCLIRequiresFlags(t *testing.T) {
	if err := cli(context.Background(), []string{"-url", "https://x/"}); err == nil {
		t.Error("missing -proxy accepted")
	}
	if err := cli(context.Background(), []string{"-url", "https://x/", "-proxy", "http://p", "-ca", "/nonexistent"}); err == nil {
		t.Error("missing CA file accepted")
	}
}

func TestBadURLs(t *testing.T) {
	dir := testpki.NewDir(t, t.TempDir())
	if _, _, err := newClient("://bad", "http://proxy", dir.File("ca.crt")); err == nil {
		t.Error("bad target accepted")
	}
	if _, _, err := newClient("https://x/", "://bad", dir.File("ca.crt")); err == nil {
		t.Error("bad proxy accepted")
	}
	if _, _, err := newClient("https:///", "http://proxy", dir.File("ca.crt")); err == nil {
		t.Error("target without a host accepted")
	}
	if err := run(context.Background(), "https://127.0.0.1:1/", "http://127.0.0.1:1", dir.File("ca.crt"), io.Discard); err == nil {
		t.Error("unreachable proxy succeeded")
	}
	if err := cli(context.Background(), []string{"-nope"}); err == nil {
		t.Error("bad flag accepted")
	}
}
