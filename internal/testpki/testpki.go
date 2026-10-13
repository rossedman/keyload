// Package testpki generates certificates for tests.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

var serial atomic.Int64

// CA is a certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	// Chain is the PEM of intermediates between this CA and its root, this
	// CA first. Empty for a root.
	Chain []byte
}

// NewCA returns a self-signed root CA valid from an hour ago for a year.
func NewCA(tb testing.TB, name string) *CA {
	tb.Helper()
	key := NewKey(tb)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	return &CA{Cert: Sign(tb, tmpl, tmpl, key.Public(), key), Key: key}
}

// Intermediate returns a CA signed by ca.
func (ca *CA) Intermediate(tb testing.TB, name string) *CA {
	tb.Helper()
	key := NewKey(tb)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	c := Sign(tb, tmpl, ca.Cert, key.Public(), ca.Key)
	return &CA{Cert: c, Key: key, Chain: append(CertPEM(c), ca.Chain...)}
}

// PEM returns the CA certificate as PEM.
func (ca *CA) PEM() []byte { return CertPEM(ca.Cert) }

// LeafOptions customize Issue.
type LeafOptions struct {
	DNSNames  []string
	IPs       []net.IP
	NotBefore time.Time // default: an hour ago
	NotAfter  time.Time // default: a day from now
	EKU       []x509.ExtKeyUsage
}

// Leaf is an issued certificate and its key.
type Leaf struct {
	Cert    *x509.Certificate
	CertPEM []byte // leaf followed by the issuing CA's intermediates
	KeyPEM  []byte
}

// TLS returns the leaf as a tls.Certificate.
func (l *Leaf) TLS(tb testing.TB) tls.Certificate {
	tb.Helper()
	c, err := tls.X509KeyPair(l.CertPEM, l.KeyPEM)
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

// Issue signs a leaf certificate. With no EKU it is valid for both server and
// client auth; with no names it is valid for localhost and 127.0.0.1.
func (ca *CA) Issue(tb testing.TB, o LeafOptions) *Leaf {
	tb.Helper()
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = time.Now().Add(24 * time.Hour)
	}
	if o.EKU == nil {
		o.EKU = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	if o.DNSNames == nil && o.IPs == nil {
		o.DNSNames = []string{"localhost"}
		o.IPs = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	key := NewKey(tb)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    o.NotBefore,
		NotAfter:     o.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  o.EKU,
		DNSNames:     o.DNSNames,
		IPAddresses:  o.IPs,
	}
	c := Sign(tb, tmpl, ca.Cert, key.Public(), ca.Key)
	return &Leaf{Cert: c, CertPEM: append(CertPEM(c), ca.Chain...), KeyPEM: KeyPEM(tb, key)}
}

// NewKey returns a P-256 key.
func NewKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

// Sign creates a certificate from tmpl signed by parent's key.
func Sign(tb testing.TB, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	tb.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		tb.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

// CertPEM encodes certificates as PEM.
func CertPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// KeyPEM encodes a private key as PKCS#8 PEM.
func KeyPEM(tb testing.TB, key crypto.Signer) []byte {
	tb.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// NoTest is a testing.TB for code outside tests, such as examples and
// example programs. Its Fatal panics; it implements nothing else.
var NoTest testing.TB = noTest{}

type noTest struct{ testing.TB }

func (noTest) Helper()                      {}
func (noTest) Fatal(args ...any)            { panic(fmt.Sprint(args...)) }
func (noTest) Fatalf(f string, args ...any) { panic(fmt.Sprintf(f, args...)) }

// Dir is a directory of PEM files laid out like a cert-manager Secret:
// tls.crt, tls.key and ca.crt.
type Dir struct {
	Path string
	CA   *CA
	Leaf *Leaf
}

// NewDir creates a CA and a leaf for localhost and writes them to path.
func NewDir(tb testing.TB, path string) *Dir {
	tb.Helper()
	d := &Dir{Path: path, CA: NewCA(tb, "example CA")}
	WriteFile(tb, d.File("ca.crt"), d.CA.PEM())
	d.Rotate(tb, LeafOptions{})
	return d
}

// File returns the path of name inside the directory.
func (d *Dir) File(name string) string { return filepath.Join(d.Path, name) }

// Rotate issues a new leaf from the directory's CA and writes it.
func (d *Dir) Rotate(tb testing.TB, o LeafOptions) *Leaf {
	tb.Helper()
	d.Leaf = d.CA.Issue(tb, o)
	WriteFile(tb, d.File("tls.crt"), d.Leaf.CertPEM)
	WriteFile(tb, d.File("tls.key"), d.Leaf.KeyPEM)
	return d.Leaf
}

// WriteFile replaces path atomically, as certificate managers do.
func WriteFile(tb testing.TB, path string, data []byte) {
	tb.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		tb.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		tb.Fatal(err)
	}
}
