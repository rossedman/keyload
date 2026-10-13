package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
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

func TestMetricsAndEvents(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("waits for the file watcher, which polls every 30s off Linux")
	}
	dir := testpki.NewDir(t, t.TempDir())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, ln, dir.Path, slog.New(slog.NewJSONHandler(logs, nil))) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	scrape := func() string {
		resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	waitMetric := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			m := scrape()
			if strings.Contains(m, want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("metrics never contained %q:\n%s", want, m)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	waitMetric(`keyload_generation{reloader="api"} 1`)
	waitMetric(`keyload_cert_not_after_seconds{reloader="api",role="leaf"}`)

	testpki.WriteFile(t, dir.File("tls.key"), []byte("oops"))
	waitMetric(`keyload_reload_total{reloader="api",result="invalid"} 1`)
	waitMetric(`keyload_generation{reloader="api"} 1`)

	dir.Rotate(t, testpki.LeafOptions{})
	waitMetric(`keyload_generation{reloader="api"} 2`)

	for _, want := range []string{`"msg":"tls reload rejected"`, `"result":"invalid"`, `"msg":"tls reload"`, `"role":"leaf"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs missing %s:\n%s", want, logs)
		}
	}
	if strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Error("logs contain key material")
	}
}

func TestCLIFlags(t *testing.T) {
	if err := cli(context.Background(), []string{"-addr", "127.0.0.1:0", "-dir", t.TempDir()}); err == nil {
		t.Error("started without certificates")
	}
}

func TestCLIServesUntilCanceled(t *testing.T) {
	dir := testpki.NewDir(t, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := cli(ctx, []string{"-addr", "127.0.0.1:0", "-dir", dir.Path}); err != nil {
		t.Fatal(err)
	}
	if err := cli(ctx, []string{"-nope"}); err == nil {
		t.Error("bad flag accepted")
	}
}
