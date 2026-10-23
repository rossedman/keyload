package keyload

import (
	"context"
	"errors"
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

// Files is a [Source] that reads PEM files. Every field is optional, but Cert
// and Key go together.
//
// Files is also a [Watcher]. On Linux it watches each file's directory, and
// the directory of its symlink target, with inotify, which is what makes
// Kubernetes Secret and ConfigMap volume updates visible. On filesystems
// where inotify misses changes (NFS, FUSE, SMB), when inotify limits are
// hit, and on other operating systems, it checks every 30 seconds instead.
type Files struct {
	Cert, Key string // leaf certificate (optionally followed by intermediates) and key; leave empty for trust-only clients
	Roots     string // CA bundle for verifying servers
	ClientCAs string // CA bundle for verifying clients
}

var (
	watchDebounce = 100 * time.Millisecond
	pollFallback  = 30 * time.Second
)

// Load reads the files. Unset fields are left nil in the Material.
func (f Files) Load(context.Context) (*Material, error) {
	if (f.Cert == "") != (f.Key == "") {
		return nil, errors.New("keyload: Files.Cert and Files.Key must be set together")
	}
	m := &Material{CertOrigin: f.Cert, KeyOrigin: f.Key, RootsOrigin: f.Roots, ClientCAsOrigin: f.ClientCAs}
	for _, file := range []struct {
		path string
		dst  *[]byte
	}{
		{f.Cert, &m.Cert},
		{f.Key, &m.Key},
		{f.Roots, &m.Roots},
		{f.ClientCAs, &m.ClientCAs},
	} {
		if file.path == "" {
			continue
		}
		b, err := os.ReadFile(file.path)
		if err != nil {
			return nil, err
		}
		if b == nil {
			b = []byte{} // configured but empty, which fails validation
		}
		*file.dst = b
	}
	return m, nil
}

// paths returns the non-empty file paths in f.
func (f Files) paths() []string {
	var ps []string
	for _, p := range []string{f.Cert, f.Key, f.Roots, f.ClientCAs} {
		if p != "" {
			ps = append(ps, p)
		}
	}
	return ps
}

// Watch calls changed when any of the files may have changed, until ctx is
// done.
func (f Files) Watch(ctx context.Context, changed func()) {
	watchFiles(ctx, f.paths(), watchDebounce, pollFallback, changed)
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
