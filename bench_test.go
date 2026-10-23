package keyload

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

func benchReloader(b *testing.B) (*Reloader, *memSource, *testpki.CA) {
	b.Helper()
	ca := testpki.NewCA(b, "ca")
	src := &memSource{m: leafMaterial(ca.Intermediate(b, "inter").Issue(b, testpki.LeafOptions{}), ca.PEM(), ca.PEM())}
	r, err := New(src, DisableWatch())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { r.Close() })
	return r, src, ca
}

// BenchmarkCurrent is the cost of reading the snapshot in service.
func BenchmarkCurrent(b *testing.B) {
	r, _, _ := benchReloader(b)
	b.ReportAllocs()
	for b.Loop() {
		_ = r.Current()
	}
}

// BenchmarkServerHandshakeConfig is what ServerConfig adds to each TLS
// handshake: GetConfigForClient returning the config cached for the current
// generation.
func BenchmarkServerHandshakeConfig(b *testing.B) {
	r, _, _ := benchReloader(b)
	cfg := r.ServerConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert})
	hello := &tls.ClientHelloInfo{}
	b.Run("cached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = cfg.GetConfigForClient(hello)
		}
	})
	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = cfg.GetConfigForClient(hello)
			}
		})
	})
	// The first handshake after a reload builds and caches a new config.
	b.Run("after-reload", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			r.cur.Store(cloneSnapshot(r.Current()))
			_, _ = cfg.GetConfigForClient(hello)
		}
	})
}

func cloneSnapshot(s *Snapshot) *Snapshot {
	c := *s
	c.Generation++
	return &c
}

// BenchmarkDialerConfig is what DialTLSContext adds to each connection:
// building a client config from the current snapshot.
func BenchmarkDialerConfig(b *testing.B) {
	r, _, _ := benchReloader(b)
	base := &tls.Config{ServerName: "localhost"}
	b.ReportAllocs()
	for b.Loop() {
		_ = r.Current().ClientConfig(base)
	}
}

// BenchmarkVerify compares Config mode's verification with the
// x509.Verify call crypto/tls makes, on the same chain.
func BenchmarkVerify(b *testing.B) {
	r, _, _ := benchReloader(b)
	leaf := r.Current().Certificate
	chain := []*x509.Certificate{leaf.Leaf}
	for _, der := range leaf.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			b.Fatal(err)
		}
		chain = append(chain, c)
	}
	b.Run("config-mode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := verifyServer(r.Current().Roots, chain, "localhost", nil); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("stdlib", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			// What crypto/tls does in Conn.verifyServerCertificate.
			inter := x509.NewCertPool()
			for _, c := range chain[1:] {
				inter.AddCert(c)
			}
			opts := x509.VerifyOptions{Roots: r.Current().Roots, Intermediates: inter, DNSName: "localhost", CurrentTime: time.Now()}
			if _, err := chain[0].Verify(opts); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkReload is the cost of a reload, which runs off the request path.
func BenchmarkReload(b *testing.B) {
	b.Run("unchanged", func(b *testing.B) {
		r, _, _ := benchReloader(b)
		b.ReportAllocs()
		for b.Loop() {
			if err := r.Reload(context.Background()); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("changed", func(b *testing.B) {
		r, src, ca := benchReloader(b)
		leaves := []*testpki.Leaf{ca.Issue(b, testpki.LeafOptions{}), ca.Issue(b, testpki.LeafOptions{})}
		b.ReportAllocs()
		i := 0
		for b.Loop() {
			i++
			src.set(leafMaterial(leaves[i%2], ca.PEM(), ca.PEM()))
			if err := r.Reload(context.Background()); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkWriteMetrics is the cost of one scrape: rendering every metric
// family for one Reloader, and for several named Reloaders on one endpoint.
func BenchmarkWriteMetrics(b *testing.B) {
	r, _, _ := benchReloader(b)
	b.Run("single", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := r.WriteMetrics(io.Discard); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("named-x4", func(b *testing.B) {
		ca := testpki.NewCA(b, "ca")
		var rs []*Reloader
		for _, name := range []string{"api", "grpc", "admin", `CN=odd "name"\`} {
			r, err := New(&memSource{m: leafMaterial(ca.Issue(b, testpki.LeafOptions{}), ca.PEM(), ca.PEM())}, DisableWatch(), Name(name))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { r.Close() })
			rs = append(rs, r)
		}
		b.ReportAllocs()
		for b.Loop() {
			if err := writeMetrics(io.Discard, rs); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestHotPathAllocations fails the build if the per-handshake path starts
// allocating.
func TestHotPathAllocations(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	r := newReloader(t, &memSource{m: leafMaterial(ca.Issue(t, testpki.LeafOptions{}), ca.PEM(), ca.PEM())}, DisableWatch())
	cfg := r.ServerConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert})
	hello := &tls.ClientHelloInfo{}
	_, _ = cfg.GetConfigForClient(hello) // build the cache

	for name, f := range map[string]func(){
		"Current":            func() { _ = r.Current() },
		"GetConfigForClient": func() { _, _ = cfg.GetConfigForClient(hello) },
		"Stats":              func() { _ = r.Stats() },
	} {
		if n := testing.AllocsPerRun(100, f); n != 0 {
			t.Errorf("%s allocates %.0f times per call, want 0", name, n)
		}
	}
}
