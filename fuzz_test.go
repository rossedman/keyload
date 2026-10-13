package keyload

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

func FuzzParseMaterial(f *testing.F) {
	ca := testpki.NewCA(f, "ca")
	inter := ca.Intermediate(f, "inter")
	leaf := inter.Issue(f, testpki.LeafOptions{})
	f.Add(leaf.CertPEM, leaf.KeyPEM, ca.PEM())
	f.Add(leaf.CertPEM[:len(leaf.CertPEM)/2], leaf.KeyPEM, ca.PEM())
	f.Add(leaf.CertPEM, leaf.KeyPEM[:30], []byte{})
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n"), []byte("junk"), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))

	f.Fuzz(func(t *testing.T, cert, key, roots []byte) {
		m := &Material{Cert: cert, Key: key, Roots: roots}
		p, err := parseMaterial(m, buildOptions{now: time.Now()})
		if err != nil {
			if _, ok := err.(*ReloadError); !ok {
				t.Fatalf("error is %T, want *ReloadError", err)
			}
			return
		}
		// Anything accepted must be usable.
		if p.cert == nil || p.cert.Leaf == nil || len(p.chain) == 0 || len(p.roots) == 0 {
			t.Fatalf("accepted material is incomplete: %+v", p)
		}
		if !p.cert.Leaf.Equal(p.chain[0]) {
			t.Fatal("tls.Certificate leaf differs from parsed chain")
		}
		if _, err := x509.ParseCertificate(p.cert.Certificate[0]); err != nil {
			t.Fatal(err)
		}
	})
}
