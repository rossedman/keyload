// Package grpccreds provides grpc-go transport credentials that follow a
// [keyload.Reloader]. It lives in its own module so the keyload core stays
// free of dependencies.
//
// Every handshake uses TLS credentials built from the reloader's current
// snapshot, so certificate verification is done by crypto/tls. Existing
// connections keep the material they were established with; new connections
// pick up reloads.
package grpccreds

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"

	"github.com/rossedman/keyload"
	"google.golang.org/grpc/credentials"
)

// Option configures the credentials returned by [New].
type Option func(*creds)

// WithTLSConfig sets the base config that each handshake's config is cloned
// from, for settings such as ClientAuth, MinVersion or ServerName.
func WithTLSConfig(base *tls.Config) Option {
	return func(c *creds) { c.base = base.Clone() }
}

// New returns transport credentials for both clients and servers. As a
// client they present the snapshot's leaf (if any) and verify servers with
// its roots; as a server they present its leaf and verify clients with its
// client CAs, according to the base config's ClientAuth.
func New(r *keyload.Reloader, opts ...Option) credentials.TransportCredentials {
	c := &creds{r: r, base: &tls.Config{MinVersion: tls.VersionTLS12}, cache: &cache{}}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type creds struct {
	r     *keyload.Reloader
	base  *tls.Config
	cache *cache
}

// cache holds the credentials built for one snapshot generation, so
// handshakes within a generation share configs (and session ticket keys).
type cache struct {
	mu     sync.Mutex
	client atomic.Pointer[entry]
	server atomic.Pointer[entry]
}

type entry struct {
	gen   uint64
	creds credentials.TransportCredentials
}

// get returns the gRPC credentials built from the current snapshot, cached
// in p until the snapshot changes.
func (c *creds) get(p *atomic.Pointer[entry], build func(*keyload.Snapshot) *tls.Config) credentials.TransportCredentials {
	snap := c.r.Current()
	if e := p.Load(); e != nil && e.gen == snap.Generation {
		return e.creds
	}
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()
	if e := p.Load(); e != nil && e.gen == snap.Generation {
		return e.creds
	}
	tc := credentials.NewTLS(build(snap))
	p.Store(&entry{gen: snap.Generation, creds: tc})
	return tc
}

// ClientHandshake runs a TLS client handshake on conn with the current
// certificates and roots.
func (c *creds) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	tc := c.get(&c.cache.client, func(s *keyload.Snapshot) *tls.Config { return s.ClientConfig(c.base) })
	return tc.ClientHandshake(ctx, authority, conn)
}

// ServerHandshake runs a TLS server handshake on conn with the current
// certificate and client CAs.
func (c *creds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	tc := c.get(&c.cache.server, func(s *keyload.Snapshot) *tls.Config { return s.ServerConfig(c.base) })
	return tc.ServerHandshake(conn)
}

// Info reports the TLS protocol information for the base config.
func (c *creds) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(c.base).Info()
}

// Clone returns a copy that shares the reloader but has its own config
// and cache.
func (c *creds) Clone() credentials.TransportCredentials {
	return &creds{r: c.r, base: c.base.Clone(), cache: &cache{}}
}

// OverrideServerName sets the server name used to verify servers.
//
// Deprecated: use WithTLSConfig with ServerName set, or grpc.WithAuthority.
func (c *creds) OverrideServerName(name string) error {
	c.base = c.base.Clone()
	c.base.ServerName = name
	c.cache = &cache{}
	return nil
}
