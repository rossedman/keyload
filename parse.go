package keyload

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Role names a piece of TLS material.
type Role string

// The roles of TLS material, as named in events and errors.
const (
	RoleLeaf      Role = "leaf"
	RoleKey       Role = "key"
	RoleRoots     Role = "roots"
	RoleClientCAs Role = "client_cas"
)

// Result is the outcome of a reload attempt, as reported in events and the
// keyload_reload_total metric.
type Result string

// The results of a reload attempt.
const (
	ResultSuccess   Result = "success"
	ResultInvalid   Result = "invalid"
	ResultReadError Result = "read_error"
)

// ReloadError describes why a reload was rejected. The previous snapshot
// stays in service.
type ReloadError struct {
	Result Result // ResultInvalid or ResultReadError
	Role   Role   // which material was at fault, if known
	Origin string // where it came from, such as a file path, if known
	Err    error
}

// Error describes the failure, naming the result, role and origin.
func (e *ReloadError) Error() string {
	var b bytes.Buffer
	b.WriteString("keyload: ")
	if e.Result == ResultReadError {
		b.WriteString("read failed")
	} else {
		b.WriteString("invalid material")
	}
	if e.Role != "" {
		fmt.Fprintf(&b, " (%s", e.Role)
		if e.Origin != "" {
			fmt.Fprintf(&b, " %s", e.Origin)
		}
		b.WriteString(")")
	}
	fmt.Fprintf(&b, ": %v", e.Err)
	return b.String()
}

// Unwrap returns the underlying error, so errors.Is matches the Err values.
func (e *ReloadError) Unwrap() error { return e.Err }

// invalid returns a ReloadError for material of role from origin that
// failed validation with err.
func invalid(role Role, origin string, err error) error {
	return &ReloadError{Result: ResultInvalid, Role: role, Origin: origin, Err: err}
}

// Validation errors, matched with errors.Is.
var (
	ErrKeyMismatch       = errors.New("private key does not match the leaf certificate")
	ErrNotYetValid       = errors.New("certificate is not yet valid")
	ErrExpired           = errors.New("certificate has expired")
	ErrExpiresTooSoon    = errors.New("certificate expires sooner than the minimum remaining lifetime")
	ErrEmptyBundle       = errors.New("no certificates found")
	ErrTruncatedPEM      = errors.New("truncated or malformed PEM block")
	ErrChainVerification = errors.New("leaf does not chain to the configured roots")
)

// decodeCerts parses every CERTIFICATE block in data. Other block types are
// skipped. A BEGIN marker that does not parse as a complete block, which is
// what a half-written file looks like, is an error.
func decodeCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if bytes.Contains(rest, []byte("-----BEGIN")) {
		return nil, ErrTruncatedPEM
	}
	return certs, nil
}

// checkPEMKey reports ErrTruncatedPEM unless data holds exactly one complete
// PEM block.
func checkPEMKey(data []byte) error {
	block, rest := pem.Decode(data)
	if block == nil || bytes.Contains(rest, []byte("-----BEGIN")) {
		return ErrTruncatedPEM
	}
	return nil
}

type buildOptions struct {
	now          time.Time
	minRemaining time.Duration
}

// parsed is material that passed validation, before overlap is applied.
type parsed struct {
	cert      *tls.Certificate
	chain     []*x509.Certificate
	notAfter  time.Time
	roots     []*x509.Certificate // nil when not configured
	clientCAs []*x509.Certificate // nil when not configured
}

// parseMaterial parses and validates m.
func parseMaterial(m *Material, o buildOptions) (*parsed, error) {
	p := &parsed{}
	if (m.Cert == nil) != (m.Key == nil) {
		return nil, invalid(RoleLeaf, m.CertOrigin, errors.New("certificate and key must be provided together"))
	}

	var err error
	if m.Roots != nil {
		if p.roots, err = parseBundle(m.Roots); err != nil {
			return nil, invalid(RoleRoots, m.RootsOrigin, err)
		}
	}
	if m.ClientCAs != nil {
		if p.clientCAs, err = parseBundle(m.ClientCAs); err != nil {
			return nil, invalid(RoleClientCAs, m.ClientCAsOrigin, err)
		}
	}

	if m.Cert == nil {
		return p, nil
	}
	chain, err := decodeCerts(m.Cert)
	if err != nil {
		return nil, invalid(RoleLeaf, m.CertOrigin, err)
	}
	if len(chain) == 0 {
		return nil, invalid(RoleLeaf, m.CertOrigin, ErrEmptyBundle)
	}
	if err := checkPEMKey(m.Key); err != nil {
		return nil, invalid(RoleKey, m.KeyOrigin, err)
	}
	cert, err := tls.X509KeyPair(m.Cert, m.Key)
	if err != nil {
		if isKeyMismatch(err) {
			err = ErrKeyMismatch
		}
		return nil, invalid(RoleKey, m.KeyOrigin, err)
	}
	cert.Leaf = chain[0]

	for i, c := range chain {
		switch {
		case o.now.Before(c.NotBefore):
			return nil, invalid(RoleLeaf, m.CertOrigin, fmt.Errorf("%w: %s (chain position %d) valid from %s", ErrNotYetValid, c.Subject, i, c.NotBefore.UTC().Format(time.RFC3339)))
		case o.now.After(c.NotAfter):
			return nil, invalid(RoleLeaf, m.CertOrigin, fmt.Errorf("%w: %s (chain position %d) expired %s", ErrExpired, c.Subject, i, c.NotAfter.UTC().Format(time.RFC3339)))
		}
		if p.notAfter.IsZero() || c.NotAfter.Before(p.notAfter) {
			p.notAfter = c.NotAfter
		}
	}
	if remaining := p.notAfter.Sub(o.now); remaining < o.minRemaining {
		return nil, invalid(RoleLeaf, m.CertOrigin, fmt.Errorf("%w: %s left, want at least %s", ErrExpiresTooSoon, remaining.Round(time.Second), o.minRemaining))
	}

	p.cert = &cert
	p.chain = chain
	return p, nil
}

// parseBundle decodes a PEM bundle of CA certificates, which must hold at
// least one.
func parseBundle(data []byte) ([]*x509.Certificate, error) {
	certs, err := decodeCerts(data)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, ErrEmptyBundle
	}
	return certs, nil
}

// isKeyMismatch reports whether err from tls.X509KeyPair means the key does
// not match the certificate.
func isKeyMismatch(err error) bool {
	return bytes.Contains([]byte(err.Error()), []byte("does not match"))
}

// verifyChain checks that the leaf chains to pool.
func verifyChain(p *parsed, pool *x509.CertPool, now time.Time) error {
	inter := x509.NewCertPool()
	for _, c := range p.chain[1:] {
		inter.AddCert(c)
	}
	_, err := p.chain[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrChainVerification, err)
	}
	return nil
}

// materialDigest hashes all four pieces of m, distinguishing a missing piece
// from an empty one, so unchanged material can be detected cheaply.
func materialDigest(m *Material) [32]byte {
	h := sha256.New()
	for _, b := range [][]byte{m.Cert, m.Key, m.Roots, m.ClientCAs} {
		var n [9]byte
		if b != nil {
			n[0] = 1
			binary.BigEndian.PutUint64(n[1:], uint64(len(b)))
		}
		h.Write(n[:])
		h.Write(b)
	}
	var d [32]byte
	h.Sum(d[:0])
	return d
}

// certKey identifies a certificate by the hash of its DER encoding.
func certKey(c *x509.Certificate) [32]byte { return sha256.Sum256(c.Raw) }

// CertInfo identifies a certificate in events without exposing key material.
type CertInfo struct {
	Role     Role
	Subject  string
	Serial   string // hex
	NotAfter time.Time
}

// certInfo describes c, in the given role, for events.
func certInfo(role Role, c *x509.Certificate) CertInfo {
	return CertInfo{Role: role, Subject: c.Subject.String(), Serial: hex.EncodeToString(c.SerialNumber.Bytes()), NotAfter: c.NotAfter}
}
