package keyload

import (
	"crypto/tls"
	"sync/atomic"
)

type cachedConfig struct {
	gen uint64
	cfg *tls.Config
}

// ServerConfig returns a server config that follows reloads. Every handshake
// gets a config built from the current snapshot: a clone of base with
// Certificates and ClientCAs from the snapshot. Certificate verification is
// left to crypto/tls.
//
// One config is built per snapshot generation and cached. The returned config
// keeps base's session ticket keys, cipher suites, ClientAuth policy and
// other settings, and session resumption keeps working across reloads.
// Resumed sessions have their client certificate re-verified against the
// current client CAs, so removing a CA also stops resumption by its clients.
//
// Handshakes use configs built from base, not from the returned config, so
// changes made to the returned config afterwards are not seen. In particular,
// set NextProtos in base: http.Server and httptest add "h2" to a copy of the
// config they are given, which the configs built here do not inherit, so
// HTTP/2 needs base.NextProtos = []string{"h2", "http/1.1"}.
//
// base.GetConfigForClient is replaced; base.GetCertificate is ignored while
// the snapshot holds a leaf.
func (r *Reloader) ServerConfig(base *tls.Config) *tls.Config {
	var outer *tls.Config
	if base == nil {
		outer = &tls.Config{}
	} else {
		outer = base.Clone()
	}
	tmpl := outer.Clone()
	var cache atomic.Pointer[cachedConfig]
	outer.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		snap := r.Current()
		if c := cache.Load(); c != nil && c.gen == snap.Generation {
			return c.cfg, nil
		}
		cfg := snap.ServerConfig(tmpl)
		cache.Store(&cachedConfig{gen: snap.Generation, cfg: cfg})
		return cfg, nil
	}
	if snap := r.Current(); snap.Certificate != nil {
		// Not used for handshakes, but some servers (http.Server.ServeTLS)
		// check that a certificate is configured before serving.
		outer.Certificates = []tls.Certificate{*snap.Certificate}
	}
	return outer
}
