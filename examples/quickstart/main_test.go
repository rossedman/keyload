package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
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

func waitFor(t *testing.T, out *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("output never contained %q:\n%s", want, out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The walkthrough in docs/getting-started.md: run, rotate, break, fix.
func TestRun(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("waits for the file watcher, which polls every 30s off Linux")
	}
	dir := t.TempDir()
	ca := newCA(t, dir)
	first := ca.issue(t, dir, time.Now().Add(24*time.Hour))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, ln, dir, 20*time.Millisecond, log.New(out, "", 0)) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	waitFor(t, out, fmt.Sprintf("hello localhost over HTTP/2.0; server certificate serial %X", first))
	second := ca.issue(t, dir, time.Now().Add(24*time.Hour))
	waitFor(t, out, fmt.Sprintf("serial %X", second))
	writeFile(t, filepath.Join(dir, "tls.key"), []byte("oops"))
	waitFor(t, out, "TLS reload rejected, still serving generation 2")
	third := ca.issue(t, dir, time.Now().Add(24*time.Hour))
	waitFor(t, out, fmt.Sprintf("serial %X", third))
}

func TestCLI(t *testing.T) {
	if err := cli(context.Background(), []string{"-dir", t.TempDir(), "-addr", "127.0.0.1:0"}); err == nil {
		t.Error("started without certificates")
	}
	if err := cli(context.Background(), []string{"-nope"}); err == nil {
		t.Error("bad flag accepted")
	}
	if err := cli(context.Background(), []string{"-addr", "256.0.0.1:0"}); err == nil {
		t.Error("bad address accepted")
	}
}
