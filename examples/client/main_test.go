package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

// syncBuffer is a concurrency-safe strings.Builder.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitFor(t *testing.T, out *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("output never contained %q:\n%s", want, out)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestClientFollowsCARotation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("waits for the file watcher, which polls every 30s off Linux")
	}
	dir := testpki.NewDir(t, t.TempDir())

	// The server's certificate comes from a CA the client doesn't trust yet.
	newCA := testpki.NewCA(t, "new CA")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello "+r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(dir.CA.Cert)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{newCA.Issue(t, testpki.LeafOptions{}).TLS(t)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	srv.StartTLS()
	defer srv.Close()

	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, srv.URL, dir.Path, 20*time.Millisecond, out) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	waitFor(t, out, "certificate signed by unknown authority")
	testpki.WriteFile(t, dir.File("ca.crt"), append(dir.CA.PEM(), newCA.PEM()...))
	waitFor(t, out, "HTTP/1.1 200 OK: hello leaf")
}

func TestCLIFlags(t *testing.T) {
	if err := cli(context.Background(), []string{"-dir", t.TempDir()}); err == nil {
		t.Error("started without certificates")
	}
}

func TestCLIRunsUntilCanceled(t *testing.T) {
	dir := testpki.NewDir(t, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := cli(ctx, []string{"-dir", dir.Path, "-url", "https://127.0.0.1:1/", "-interval", "20ms"}); err != nil {
		t.Fatal(err)
	}
	if err := cli(ctx, []string{"-nope"}); err == nil {
		t.Error("bad flag accepted")
	}
	if err := get(ctx, http.DefaultClient, "://bad", io.Discard); err == nil {
		t.Error("bad URL accepted")
	}
}
