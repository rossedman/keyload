package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

func TestServerPicksUpRotatedCertificate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("waits for the file watcher, which polls every 30s off Linux")
	}
	dir := testpki.NewDir(t, t.TempDir())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, ln, dir.Path, slog.New(slog.DiscardHandler)) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	roots := x509.NewCertPool()
	roots.AddCert(dir.CA.Cert)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{dir.CA.Issue(t, testpki.LeafOptions{}).TLS(t)}},
		ForceAttemptHTTP2: true,
		DisableKeepAlives: true,
	}}
	get := func() (serial string, body string) {
		t.Helper()
		resp, err := client.Get("https://" + ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.ProtoMajor != 2 {
			t.Errorf("got %s, want HTTP/2", resp.Proto)
		}
		return resp.TLS.PeerCertificates[0].SerialNumber.String(), string(b)
	}

	first, body := get()
	if body != "hello, leaf\n" {
		t.Errorf("body = %q", body)
	}
	want := dir.Rotate(t, testpki.LeafOptions{}).Cert.SerialNumber.String()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := get()
		if got == want {
			break
		}
		if got != first || time.Now().After(deadline) {
			t.Fatalf("serving serial %s, want %s", got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A broken key is rejected and the rotated certificate keeps serving.
	testpki.WriteFile(t, dir.File("tls.key"), []byte("oops"))
	time.Sleep(300 * time.Millisecond)
	if got, _ := get(); got != want {
		t.Errorf("after a bad write, serving serial %s, want %s", got, want)
	}
}

func TestBadFirstLoadFailsStartup(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := run(context.Background(), ln, t.TempDir(), slog.New(slog.DiscardHandler)); err == nil {
		t.Error("run started without certificates")
	}
}

func TestCLIFlags(t *testing.T) {
	if err := cli(context.Background(), []string{"-nope"}); err == nil {
		t.Error("bad flag accepted")
	}
}

func TestCLIServesUntilCanceled(t *testing.T) {
	dir := testpki.NewDir(t, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := cli(ctx, []string{"-addr", "127.0.0.1:0", "-dir", dir.Path}); err != nil {
		t.Fatal(err)
	}
	if err := cli(ctx, []string{"-addr", "256.0.0.1:0", "-dir", dir.Path}); err == nil {
		t.Error("bad address accepted")
	}
}

func TestLeafExpiry(t *testing.T) {
	if got := leafExpiry(nil); got != "unchanged" {
		t.Errorf("leafExpiry(nil) = %q", got)
	}
}
