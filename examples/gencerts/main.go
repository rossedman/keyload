// Command gencerts writes a throwaway CA and a certificate for localhost to a
// directory, laid out like a cert-manager Secret (ca.crt, tls.crt, tls.key),
// so you can try the other examples. With -rotate it issues a new
// certificate from the existing CA, the way a renewal would.
//
//	go run ./examples/gencerts -dir /tmp/keyload
//	go run ./examples/gencerts -dir /tmp/keyload -rotate
//	go run ./examples/gencerts -dir /tmp/keyload -rotate -ttl 30m
//
// The CA's key is kept in ca.key. These certificates are for demos only.
package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

func run(dir string, rotate bool, ttl time.Duration) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tb := testpki.NoTest
	d := &testpki.Dir{Path: dir}
	if rotate {
		ca, err := loadCA(dir)
		if err != nil {
			return fmt.Errorf("-rotate needs an existing CA in %s: %w", dir, err)
		}
		d.CA = ca
	} else {
		d.CA = testpki.NewCA(tb, "keyload example CA")
		testpki.WriteFile(tb, d.File("ca.crt"), d.CA.PEM())
		testpki.WriteFile(tb, d.File("ca.key"), testpki.KeyPEM(tb, d.CA.Key))
	}
	leaf := d.Rotate(tb, testpki.LeafOptions{NotAfter: time.Now().Add(ttl)})
	fmt.Printf("wrote %s (serial %s, expires %s)\n", d.File("tls.crt"), leaf.Cert.SerialNumber, leaf.Cert.NotAfter.Format(time.RFC3339))
	return nil
}

func loadCA(dir string) (*testpki.CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("ca.crt or ca.key is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca.key is not a signing key")
	}
	return &testpki.CA{Cert: cert, Key: signer}, nil
}

func main() {
	dir := flag.String("dir", "keyload-certs", "directory to write ca.crt, tls.crt and tls.key to")
	rotate := flag.Bool("rotate", false, "issue a new certificate from the existing CA")
	ttl := flag.Duration("ttl", 24*time.Hour, "lifetime of the issued certificate")
	flag.Parse()
	if err := run(*dir, *rotate, *ttl); err != nil {
		log.Fatal(err)
	}
}
