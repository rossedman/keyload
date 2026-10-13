package keyload

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

// fastRetries makes failed reloads give up quickly in tests.
func fastRetries() Option {
	return func(o *options) { o.retryDelay = time.Millisecond }
}

func withClock(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// writeFile replaces path atomically, as cert-manager and most tools do.
func writeFile(t testing.TB, path string, data []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// pkiDir is a directory of PEM files for one party.
type pkiDir struct {
	dir   string
	files Files
}

func newPKIDir(t testing.TB, leaf *testpki.Leaf, roots, clientCAs []byte) *pkiDir {
	t.Helper()
	d := &pkiDir{dir: t.TempDir()}
	d.files = Files{
		Cert:      filepath.Join(d.dir, "tls.crt"),
		Key:       filepath.Join(d.dir, "tls.key"),
		Roots:     filepath.Join(d.dir, "ca.crt"),
		ClientCAs: filepath.Join(d.dir, "client-ca.crt"),
	}
	d.write(t, leaf, roots, clientCAs)
	return d
}

func (d *pkiDir) write(t testing.TB, leaf *testpki.Leaf, roots, clientCAs []byte) {
	t.Helper()
	if leaf != nil {
		writeFile(t, d.files.Cert, leaf.CertPEM)
		writeFile(t, d.files.Key, leaf.KeyPEM)
	}
	if roots != nil {
		writeFile(t, d.files.Roots, roots)
	}
	if clientCAs != nil {
		writeFile(t, d.files.ClientCAs, clientCAs)
	}
}

// memSource is a Source whose material tests set directly.
type memSource struct {
	mu   sync.Mutex
	m    Material
	err  error
	hook func(n int) (*Material, error) // overrides m when set; n counts calls
	n    int
}

func (s *memSource) Load(context.Context) (*Material, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	if s.hook != nil {
		return s.hook(s.n)
	}
	if s.err != nil {
		return nil, s.err
	}
	m := s.m
	return &m, nil
}

func (s *memSource) set(m Material) {
	s.mu.Lock()
	s.m, s.err = m, nil
	s.mu.Unlock()
}

func leafMaterial(leaf *testpki.Leaf, roots, clientCAs []byte) Material {
	return Material{Cert: leaf.CertPEM, Key: leaf.KeyPEM, Roots: roots, ClientCAs: clientCAs}
}

func newReloader(t testing.TB, src Source, opts ...Option) *Reloader {
	t.Helper()
	r, err := New(context.Background(), src, append([]Option{fastRetries()}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// events collects OnReload events.
type events struct {
	mu  sync.Mutex
	ch  chan Event
	all []Event
}

func newEvents() *events { return &events{ch: make(chan Event, 100)} }

func (e *events) option() Option {
	return OnReload(func(ev Event) {
		e.mu.Lock()
		e.all = append(e.all, ev)
		e.mu.Unlock()
		select {
		case e.ch <- ev:
		default:
		}
	})
}

func (e *events) next(t testing.TB, timeout time.Duration) Event {
	t.Helper()
	select {
	case ev := <-e.ch:
		return ev
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a reload event")
		return Event{}
	}
}

// drain discards buffered events.
func (e *events) drain() {
	for {
		select {
		case <-e.ch:
		default:
			return
		}
	}
}
