package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
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
	// Each run is a new process; serials must still differ.
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Error("rotate reused the serial number")
	}
	if first.Leaf.Subject.CommonName != "localhost" {
		t.Errorf("CommonName = %q, want localhost", first.Leaf.Subject.CommonName)
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

// TestMain lets the test binary act as gencerts, so tests can run it as
// separate processes the way users do.
func TestMain(m *testing.M) {
	if os.Getenv("GENCERTS_RUN_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Serial numbers must differ even when each certificate comes from a
// separate gencerts process (it once numbered serials from 1 in every run).
func TestRotateAcrossProcessesUsesNewSerials(t *testing.T) {
	dir := t.TempDir()
	gencerts := func(args ...string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], append([]string{"-dir", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GENCERTS_RUN_MAIN=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("gencerts %v: %v\n%s", args, err, out)
		}
	}
	serial := func() string {
		t.Helper()
		c, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf.SerialNumber.String()
	}
	gencerts()
	seen := map[string]bool{serial(): true}
	for i := 0; i < 3; i++ {
		gencerts("-rotate")
		s := serial()
		if seen[s] {
			t.Fatalf("rotation %d reused serial %s", i+1, s)
		}
		seen[s] = true
	}
}
