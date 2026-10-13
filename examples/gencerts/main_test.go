package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateAndRotate(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	first, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))

	if err := run(dir, true, time.Hour); err != nil {
		t.Fatal(err)
	}
	second, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Error("rotate did not issue a new certificate")
	}
	if ca2, _ := os.ReadFile(filepath.Join(dir, "ca.crt")); string(ca) != string(ca2) {
		t.Error("rotate replaced the CA")
	}
	if err := second.Leaf.CheckSignatureFrom(mustParseCA(t, ca)); err != nil {
		t.Errorf("rotated certificate not signed by the CA: %v", err)
	}
}

func TestRotateNeedsCA(t *testing.T) {
	if err := run(t.TempDir(), true, time.Hour); err == nil {
		t.Error("rotate without a CA succeeded")
	}
}

func mustParseCA(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(pemBytes)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadCAErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.crt", "not pem")
	if _, err := loadCA(dir); err == nil {
		t.Error("missing ca.key accepted")
	}
	write("ca.key", "not pem")
	if _, err := loadCA(dir); err == nil {
		t.Error("non-PEM files accepted")
	}
	write("ca.crt", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	write("ca.key", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	if _, err := loadCA(dir); err == nil {
		t.Error("garbage certificate accepted")
	}
	if err := run(filepath.Join(dir, "ca.crt", "sub"), false, time.Hour); err == nil {
		t.Error("unwritable directory accepted")
	}
}
