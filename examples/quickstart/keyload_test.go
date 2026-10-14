package main

// How to test code that uses keyload: write files to t.TempDir(), and call
// Reload to apply a change at once instead of waiting for the file watcher.

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rossedman/keyload"
)

func files(dir string) keyload.Files {
	return keyload.Files{
		Cert:      filepath.Join(dir, "tls.crt"),
		Key:       filepath.Join(dir, "tls.key"),
		Roots:     filepath.Join(dir, "ca.crt"),
		ClientCAs: filepath.Join(dir, "ca.crt"),
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)
	first := ca.issue(t, dir, time.Now().Add(24*time.Hour))

	r, err := keyload.New(files(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	srv.EnableHTTP2 = true
	srv.TLS = r.ServerConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"h2", "http/1.1"}})
	srv.StartTLS()
	defer srv.Close()

	tr := &http.Transport{ForceAttemptHTTP2: true}
	if err := r.ConfigureTransport(tr, &tls.Config{ServerName: "localhost"}); err != nil {
		t.Fatal(err)
	}
	serverSerial := func() *big.Int {
		t.Helper()
		defer tr.CloseIdleConnections() // the next request makes a new connection
		resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Errorf("got %s, want HTTP/2", resp.Proto)
		}
		return resp.TLS.PeerCertificates[0].SerialNumber
	}

	if got := serverSerial(); got.Cmp(first) != 0 {
		t.Fatalf("serving %v, want %v", got, first)
	}

	// Rotate, and apply it now rather than waiting for the watcher.
	second := ca.issue(t, dir, time.Now().Add(24*time.Hour))
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := serverSerial(); got.Cmp(second) != 0 {
		t.Fatalf("after rotation, serving %v, want %v", got, second)
	}

	// A broken key is rejected, and the second certificate keeps serving.
	writeFile(t, filepath.Join(dir, "tls.key"), []byte("oops"))
	err = r.Reload(context.Background())
	var re *keyload.ReloadError
	if !errors.As(err, &re) || re.Role != keyload.RoleKey {
		t.Fatalf("Reload() = %v, want a key error", err)
	}
	if got := serverSerial(); got.Cmp(second) != 0 {
		t.Fatalf("after a broken key, serving %v, want %v", got, second)
	}
}

func TestMinRemaining(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)
	ca.issue(t, dir, time.Now().Add(10*time.Minute))
	if _, err := keyload.New(files(dir), keyload.MinRemaining(time.Hour)); !errors.Is(err, keyload.ErrExpiresTooSoon) {
		t.Fatalf("New() = %v, want ErrExpiresTooSoon", err)
	}
}

func TestProxyIsRefused(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, dir)
	ca.issue(t, dir, time.Now().Add(24*time.Hour))
	r, err := keyload.New(files(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if err := r.ConfigureTransport(tr, nil); !errors.Is(err, keyload.ErrProxyConfigured) {
		t.Fatalf("ConfigureTransport() = %v, want ErrProxyConfigured", err)
	}
}
