package keyload

import (
	"context"
	"fmt"
	"os"
	"time"
)

// Material is the raw PEM that a [Source] returns.
//
// A nil field means the source does not provide that piece of material. A
// non-nil but empty field means it is configured and empty, which fails
// validation.
type Material struct {
	Cert      []byte // leaf certificate, optionally followed by intermediates
	Key       []byte // private key for the leaf
	Roots     []byte // CA bundle for verifying servers
	ClientCAs []byte // CA bundle for verifying clients

	// Origins say where each field came from, such as a file path. They are
	// used only in errors and events.
	CertOrigin, KeyOrigin, RootsOrigin, ClientCAsOrigin string
}

// Source loads TLS material. Implementations return raw PEM and leave
// parsing and validation to the [Reloader].
type Source interface {
	Load(ctx context.Context) (*Material, error)
}

// Watcher is implemented by sources that can tell when their material may
// have changed. The [Reloader] calls Watch once, in its own goroutine, and
// reloads whenever changed is called. Spurious calls are cheap: a reload of
// unchanged material is a no-op.
type Watcher interface {
	// Watch calls changed whenever the material may have changed, until ctx
	// is done.
	Watch(ctx context.Context, changed func())
}

// SourceFunc adapts a function to the [Source] interface.
type SourceFunc func(ctx context.Context) (*Material, error)

// Load calls f(ctx).
func (f SourceFunc) Load(ctx context.Context) (*Material, error) { return f(ctx) }

// Files names the PEM files to load. Every field is optional, but a set
// Cert requires a set Key and the other way round.
type Files struct {
	Cert, Key string // leaf; leave empty for trust-only clients
	Roots     string // CA bundle for verifying servers
	ClientCAs string // CA bundle for verifying clients
}

const (
	defaultDebounce     = 100 * time.Millisecond
	defaultPollFallback = 30 * time.Second
)

// FromFiles returns a [Source] that reads the given files. It also
// implements [Watcher]: it watches each file's directory (and the directory
// of its symlink target) with inotify on Linux, so Kubernetes Secret volume
// updates are seen. On filesystems without inotify support (NFS, FUSE, SMB),
// when inotify limits are hit, or on other operating systems, it polls every
// 30 seconds instead.
func FromFiles(f Files) Source {
	return &fileSource{files: f, debounce: defaultDebounce, poll: defaultPollFallback}
}

type fileSource struct {
	files    Files
	debounce time.Duration
	poll     time.Duration
}

func (s *fileSource) Load(ctx context.Context) (*Material, error) {
	if (s.files.Cert == "") != (s.files.Key == "") {
		return nil, fmt.Errorf("keyload: Files.Cert and Files.Key must be set together")
	}
	m := &Material{
		CertOrigin:      s.files.Cert,
		KeyOrigin:       s.files.Key,
		RootsOrigin:     s.files.Roots,
		ClientCAsOrigin: s.files.ClientCAs,
	}
	for _, f := range []struct {
		path string
		dst  *[]byte
	}{
		{s.files.Cert, &m.Cert},
		{s.files.Key, &m.Key},
		{s.files.Roots, &m.Roots},
		{s.files.ClientCAs, &m.ClientCAs},
	} {
		if f.path == "" {
			continue
		}
		b, err := os.ReadFile(f.path)
		if err != nil {
			return nil, err
		}
		if b == nil {
			b = []byte{}
		}
		*f.dst = b
	}
	return m, nil
}

func (s *fileSource) paths() []string {
	var ps []string
	for _, p := range []string{s.files.Cert, s.files.Key, s.files.Roots, s.files.ClientCAs} {
		if p != "" {
			ps = append(ps, p)
		}
	}
	return ps
}

func (s *fileSource) Watch(ctx context.Context, changed func()) {
	watchFiles(ctx, s.paths(), s.debounce, s.poll, changed)
}

// pollFiles calls changed every interval until ctx is done.
func pollFiles(ctx context.Context, interval time.Duration, changed func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed()
		}
	}
}
