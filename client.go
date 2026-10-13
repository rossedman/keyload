package keyload

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// DialTLSContext returns a dial function that builds a fresh client config
// from the current snapshot for every connection: a clone of base with
// RootCAs from the snapshot and, when base has no client certificate, the
// snapshot's leaf. When base.ServerName is empty it is taken from the dialed
// address. Certificate verification is left to crypto/tls.
//
// Use it as http.Transport.DialTLSContext, or prefer
// [Reloader.ConfigureTransport], which also refuses transports that use a
// proxy. For HTTP/2 set base.NextProtos to []string{"h2", "http/1.1"}.
func (r *Reloader) DialTLSContext(base *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if base == nil {
		base = &tls.Config{}
	} else {
		base = base.Clone()
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		cfg := r.Current().ClientConfig(base)
		if cfg.ServerName == "" {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			cfg.ServerName = host
		}
		d := tls.Dialer{Config: cfg}
		return d.DialContext(ctx, network, addr)
	}
}

// ErrProxyConfigured is returned by [Reloader.ConfigureTransport] for a
// transport that sends HTTPS through a proxy. http.Transport does not use
// DialTLSContext for proxied HTTPS requests, so the reloaded roots would be
// silently ignored. Use [Reloader.ClientConfig] for such transports.
var ErrProxyConfigured = errors.New("keyload: transport uses an HTTPS proxy, which bypasses DialTLSContext; use Reloader.ClientConfig as TLSClientConfig instead")

// ConfigureTransport sets t.DialTLSContext to [Reloader.DialTLSContext] with
// base. It returns [ErrProxyConfigured] if t.Proxy would send HTTPS requests
// through a proxy, since http.Transport then does its own TLS with
// TLSClientConfig. When t.ForceAttemptHTTP2 is set and base.NextProtos is
// empty, it offers "h2" and "http/1.1".
func (r *Reloader) ConfigureTransport(t *http.Transport, base *tls.Config) error {
	if t.Proxy != nil {
		probe := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "keyload.invalid"}, Header: http.Header{}}
		u, err := t.Proxy(probe)
		if err != nil || u != nil {
			return ErrProxyConfigured
		}
	}
	if base == nil {
		base = &tls.Config{}
	} else {
		base = base.Clone()
	}
	if t.ForceAttemptHTTP2 && len(base.NextProtos) == 0 {
		base.NextProtos = []string{"h2", "http/1.1"}
	}
	t.DialTLSContext = r.DialTLSContext(base)
	return nil
}

// ErrNoServerName is returned by [Reloader.ClientConfig] when base has no
// ServerName. Without one there would be no hostname check.
var ErrNoServerName = errors.New("keyload: ClientConfig requires base.ServerName; without it the server's hostname would not be checked")

// ClientConfig returns a client config for libraries that only accept a
// *tls.Config and never let you build one per connection ("Config mode").
// It is the only place keyload verifies certificates itself; prefer
// [Reloader.DialTLSContext] or the grpccreds module where you can.
//
// The returned config sets InsecureSkipVerify and verifies the server in
// VerifyConnection, on every handshake including resumed ones, with
// x509.Certificate.Verify and the same options crypto/tls uses: the current
// snapshot's roots (system roots if none are configured), the peer's
// intermediates, DNSName set to base.ServerName, ServerAuth key usage and
// base.Time as the clock. base.VerifyConnection, if set, runs after a
// successful check.
//
// Because crypto/tls does not verify in this mode,
// tls.ConnectionState.VerifiedChains is empty and base.VerifyPeerCertificate
// receives nil verifiedChains.
//
// ClientConfig returns [ErrNoServerName] if base.ServerName is empty, and an
// error if base already sets InsecureSkipVerify. When base has no client
// certificate the snapshot's leaf is presented, following reloads.
func (r *Reloader) ClientConfig(base *tls.Config) (*tls.Config, error) {
	if base == nil || base.ServerName == "" {
		return nil, ErrNoServerName
	}
	if base.InsecureSkipVerify {
		return nil, errors.New("keyload: ClientConfig base must not set InsecureSkipVerify")
	}
	cfg := base.Clone()
	serverName, timeFn, next := base.ServerName, base.Time, base.VerifyConnection
	cfg.InsecureSkipVerify = true
	cfg.RootCAs = nil
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := verifyServer(r.Current().Roots, cs.PeerCertificates, serverName, timeFn); err != nil {
			return err
		}
		if next != nil {
			return next(cs)
		}
		return nil
	}
	if len(cfg.Certificates) == 0 && cfg.GetClientCertificate == nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if c := r.Current().Certificate; c != nil {
				return c, nil
			}
			return &tls.Certificate{}, nil
		}
	}
	return cfg, nil
}

// verifyServer mirrors crypto/tls's client-side verification
// (Conn.verifyServerCertificate).
func verifyServer(roots *x509.CertPool, certs []*x509.Certificate, serverName string, timeFn func() time.Time) error {
	if len(certs) == 0 {
		return errors.New("tls: server did not provide a certificate")
	}
	now := time.Now()
	if timeFn != nil {
		now = timeFn()
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		DNSName:       serverName,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
	}
	return nil
}
