package keyload

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

// Snapshot is one immutable, validated set of TLS material. A Snapshot is
// never modified after it is published; treat every field as read-only.
type Snapshot struct {
	Certificate *tls.Certificate // leaf + chain + key; nil for trust-only clients
	Roots       *x509.CertPool   // verifies servers (client side); nil means system roots
	ClientCAs   *x509.CertPool   // verifies clients (server side)

	// RootCerts and ClientCACerts list the certificates in Roots and
	// ClientCAs, including any outgoing CAs kept by [OverlapWindow].
	RootCerts     []*x509.Certificate
	ClientCACerts []*x509.Certificate

	Generation uint64
	LoadedAt   time.Time
	NotAfter   time.Time // earliest expiry in the leaf chain; zero without a leaf

	// Fields used by the next reload.
	digest         [32]byte            // of the source material
	rootBundle     []*x509.Certificate // Roots as loaded, without overlap
	clientCABundle []*x509.Certificate // ClientCAs as loaded, without overlap
}

// ServerConfig returns a static server config built from this snapshot:
// a clone of base with Certificates and ClientCAs taken from the snapshot.
// Most callers want [Reloader.ServerConfig], which follows reloads.
func (s *Snapshot) ServerConfig(base *tls.Config) *tls.Config {
	var cfg *tls.Config
	if base == nil {
		cfg = &tls.Config{}
	} else {
		cfg = base.Clone()
	}
	cfg.GetConfigForClient = nil
	if s.Certificate != nil {
		cfg.Certificates = []tls.Certificate{*s.Certificate}
		cfg.GetCertificate = nil
	}
	if s.ClientCAs != nil {
		cfg.ClientCAs = s.ClientCAs
		cfg.VerifyConnection = verifyResumedClient(s.ClientCAs, cfg.ClientAuth, cfg.Time, cfg.VerifyConnection)
	}
	return cfg
}

// ClientConfig returns a static client config built from this snapshot: a
// clone of base with RootCAs taken from the snapshot and, when base has no
// client certificate of its own, the snapshot's leaf. Verification is left
// to crypto/tls. Most callers want [Reloader.DialTLSContext].
func (s *Snapshot) ClientConfig(base *tls.Config) *tls.Config {
	var cfg *tls.Config
	if base == nil {
		cfg = &tls.Config{}
	} else {
		cfg = base.Clone()
	}
	if s.Roots != nil {
		cfg.RootCAs = s.Roots
	}
	if s.Certificate != nil && len(cfg.Certificates) == 0 && cfg.GetClientCertificate == nil {
		cfg.Certificates = []tls.Certificate{*s.Certificate}
	}
	return cfg
}

// verifyResumedClient re-checks a resumed session's client certificate
// against the current client CAs. crypto/tls does not re-verify client
// certificates on resumption, so without this a client whose CA was removed
// could keep resuming sessions issued before the reload.
func verifyResumedClient(pool *x509.CertPool, auth tls.ClientAuthType, timeFn func() time.Time, next func(tls.ConnectionState) error) func(tls.ConnectionState) error {
	if auth < tls.VerifyClientCertIfGiven {
		return next
	}
	return func(cs tls.ConnectionState) error {
		if cs.DidResume && len(cs.PeerCertificates) > 0 {
			now := time.Now()
			if timeFn != nil {
				now = timeFn()
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         pool,
				Intermediates: inter,
				CurrentTime:   now,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			})
			if err != nil {
				return &tls.CertificateVerificationError{UnverifiedCertificates: cs.PeerCertificates, Err: err}
			}
		}
		if next != nil {
			return next(cs)
		}
		return nil
	}
}
