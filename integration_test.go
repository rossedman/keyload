package keyload

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

// connPair returns two ends of a loopback TCP connection. Unlike net.Pipe it
// is buffered, so both sides can send alerts at once without deadlocking.
func connPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("accept failed")
	}
	return c, s
}

// handshake runs a TLS handshake over loopback and returns the client's
// connection state.
func handshake(t testing.TB, client, server *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	c, s := connPair(t)
	defer c.Close()
	defer s.Close()
	srvErr := make(chan error, 1)
	go func() {
		ts := tls.Server(s, server)
		err := ts.Handshake()
		if err == nil {
			// Read so TLS 1.3 session tickets are flushed to the client.
			_, _ = ts.Write([]byte("x"))
		}
		srvErr <- err
		s.Close()
	}()
	tc := tls.Client(c, client)
	err := tc.Handshake()
	if err == nil {
		var b [1]byte
		_, _ = io.ReadFull(tc, b[:])
	}
	serr := <-srvErr
	if err == nil {
		err = serr
	}
	return tc.ConnectionState(), err
}

func pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func TestServerModeFollowsReloads(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	clientCA, clientCA2 := testpki.NewCA(t, "clients"), testpki.NewCA(t, "clients2")
	first := ca.Issue(t, testpki.LeafOptions{})
	src := &memSource{m: leafMaterial(first, nil, clientCA.PEM())}
	r := newReloader(t, src)
	srvCfg := r.ServerConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert})

	clientCert := clientCA.Issue(t, testpki.LeafOptions{}).TLS(t)
	client := &tls.Config{ServerName: "localhost", RootCAs: pool(ca.Cert), Certificates: []tls.Certificate{clientCert}}

	cs, err := handshake(t, client, srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	if !cs.PeerCertificates[0].Equal(first.Cert) {
		t.Fatal("server did not present the first leaf")
	}

	second := ca.Issue(t, testpki.LeafOptions{})
	src.set(leafMaterial(second, nil, clientCA2.PEM()))
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := handshake(t, client, srvCfg); err == nil {
		t.Fatal("client signed by a removed CA was accepted")
	}
	client.Certificates = []tls.Certificate{clientCA2.Issue(t, testpki.LeafOptions{}).TLS(t)}
	cs, err = handshake(t, client, srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	if !cs.PeerCertificates[0].Equal(second.Cert) {
		t.Error("server did not present the reloaded leaf")
	}
}

func TestServerModeCachesPerGeneration(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	src := &memSource{m: leafMaterial(ca.Issue(t, testpki.LeafOptions{}), nil, nil)}
	r := newReloader(t, src)
	cfg := r.ServerConfig(nil)
	a, _ := cfg.GetConfigForClient(nil)
	b, _ := cfg.GetConfigForClient(nil)
	if a != b {
		t.Error("config rebuilt within one generation")
	}
	src.set(leafMaterial(ca.Issue(t, testpki.LeafOptions{}), nil, nil))
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, _ := cfg.GetConfigForClient(nil); c == a {
		t.Error("config not rebuilt after a reload")
	}
}

// Session tickets survive a reload, but a resumed client whose CA was removed
// is refused.
func TestServerModeResumption(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	clientCA, otherCA := testpki.NewCA(t, "clients"), testpki.NewCA(t, "other")
	src := &memSource{m: leafMaterial(ca.Issue(t, testpki.LeafOptions{}), nil, clientCA.PEM())}
	r := newReloader(t, src)
	srvCfg := r.ServerConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert})

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			src.set(leafMaterial(ca.Issue(t, testpki.LeafOptions{}), nil, clientCA.PEM()))
			if err := r.Reload(context.Background()); err != nil {
				t.Fatal(err)
			}
			client := &tls.Config{
				ServerName: "localhost", RootCAs: pool(ca.Cert), MaxVersion: version,
				Certificates:       []tls.Certificate{clientCA.Issue(t, testpki.LeafOptions{}).TLS(t)},
				ClientSessionCache: tls.NewLRUClientSessionCache(8),
			}
			if _, err := handshake(t, client, srvCfg); err != nil {
				t.Fatal(err)
			}

			// A reload that keeps the client CA: resumption still works.
			src.set(leafMaterial(ca.Issue(t, testpki.LeafOptions{}), nil, append(clientCA.PEM(), otherCA.PEM()...)))
			if err := r.Reload(context.Background()); err != nil {
				t.Fatal(err)
			}
			cs, err := handshake(t, client, srvCfg)
			if err != nil {
				t.Fatal(err)
			}
			if !cs.DidResume {
				t.Fatal("session did not resume across a reload")
			}

			// A reload that drops the client CA: resumption is refused.
			src.set(leafMaterial(ca.Issue(t, testpki.LeafOptions{}), nil, otherCA.PEM()))
			if err := r.Reload(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := handshake(t, client, srvCfg); err == nil {
				t.Fatal("resumed session accepted after its client CA was removed")
			}
		})
	}
}

func TestDialerModeFollowsReloads(t *testing.T) {
	ca, ca2 := testpki.NewCA(t, "ca"), testpki.NewCA(t, "ca2")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	srvLeaf := ca2.Issue(t, testpki.LeafOptions{}).TLS(t)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvLeaf}}
	srv.StartTLS()
	defer srv.Close()

	src := &memSource{m: Material{Roots: ca.PEM()}}
	r := newReloader(t, src)
	tr := &http.Transport{}
	if err := r.ConfigureTransport(tr, nil); err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr}

	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("request succeeded against an untrusted server")
	}
	src.set(Material{Roots: ca2.PEM()})
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestConfigureTransportRefusesProxy(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	r := newReloader(t, &memSource{m: Material{Roots: ca.PEM()}})
	tr := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "proxy:3128"})}
	if err := r.ConfigureTransport(tr, nil); !errors.Is(err, ErrProxyConfigured) {
		t.Errorf("ConfigureTransport() = %v, want ErrProxyConfigured", err)
	}
	tr = &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return nil, nil }}
	if err := r.ConfigureTransport(tr, nil); err != nil {
		t.Errorf("ConfigureTransport() with a no-op proxy func = %v", err)
	}
}

func TestClientConfigRequiresServerName(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	r := newReloader(t, &memSource{m: Material{Roots: ca.PEM()}})
	if _, err := r.ClientConfig(&tls.Config{}); !errors.Is(err, ErrNoServerName) {
		t.Errorf("ClientConfig() = %v, want ErrNoServerName", err)
	}
	if _, err := r.ClientConfig(nil); !errors.Is(err, ErrNoServerName) {
		t.Errorf("ClientConfig(nil) = %v, want ErrNoServerName", err)
	}
	if _, err := r.ClientConfig(&tls.Config{ServerName: "x", InsecureSkipVerify: true}); err == nil {
		t.Error("ClientConfig() accepted a base with InsecureSkipVerify")
	}
}

func TestClientConfigMode(t *testing.T) {
	ca, ca2 := testpki.NewCA(t, "ca"), testpki.NewCA(t, "ca2")
	server := &tls.Config{Certificates: []tls.Certificate{ca.Issue(t, testpki.LeafOptions{DNSNames: []string{"api.example.com"}}).TLS(t)}}
	src := &memSource{m: Material{Roots: ca.PEM()}}
	r := newReloader(t, src)

	var userCalled atomic.Int32
	cfg, err := r.ClientConfig(&tls.Config{
		ServerName:         "api.example.com",
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
		VerifyConnection:   func(tls.ConnectionState) error { userCalled.Add(1); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := handshake(t, cfg, server)
	if err != nil {
		t.Fatal(err)
	}
	if userCalled.Load() != 1 {
		t.Error("caller's VerifyConnection not chained")
	}
	if len(cs.VerifiedChains) != 0 {
		t.Error("VerifiedChains should be empty in Config mode")
	}

	// Wrong host.
	wrong, err := r.ClientConfig(&tls.Config{ServerName: "other.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handshake(t, wrong, server); err == nil {
		t.Error("hostname mismatch accepted")
	}

	// Roots reload: the old CA is no longer trusted, even for a resumed
	// session.
	src.set(Material{Roots: ca2.PEM()})
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	cs, err = handshake(t, cfg, server)
	if err == nil {
		t.Fatalf("server accepted after its CA was removed (resumed=%v)", cs.DidResume)
	}
	var cve *tls.CertificateVerificationError
	if !errors.As(err, &cve) {
		t.Errorf("error = %v, want a CertificateVerificationError", err)
	}
}

// VerifyConnection runs on resumed handshakes in Config mode.
func TestClientConfigVerifiesResumedSessions(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	server := &tls.Config{Certificates: []tls.Certificate{ca.Issue(t, testpki.LeafOptions{}).TLS(t)}}
	r := newReloader(t, &memSource{m: Material{Roots: ca.PEM()}})
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		var calls, resumed atomic.Int32
		cfg, err := r.ClientConfig(&tls.Config{
			ServerName: "localhost", MaxVersion: version,
			ClientSessionCache: tls.NewLRUClientSessionCache(8),
			VerifyConnection: func(cs tls.ConnectionState) error {
				calls.Add(1)
				if cs.DidResume {
					resumed.Add(1)
				}
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if _, err := handshake(t, cfg, server); err != nil {
				t.Fatal(err)
			}
		}
		if calls.Load() != 2 || resumed.Load() != 1 {
			t.Errorf("%s: VerifyConnection calls = %d, resumed = %d; want 2 and 1", tls.VersionName(version), calls.Load(), resumed.Load())
		}
	}
}

func TestClientConfigPresentsReloadedLeaf(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	first, second := ca.Issue(t, testpki.LeafOptions{}), ca.Issue(t, testpki.LeafOptions{})
	src := &memSource{m: leafMaterial(first, ca.PEM(), nil)}
	r := newReloader(t, src)
	var seen *x509.Certificate
	server := &tls.Config{
		Certificates: []tls.Certificate{ca.Issue(t, testpki.LeafOptions{}).TLS(t)},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool(ca.Cert),
		VerifyConnection: func(cs tls.ConnectionState) error { seen = cs.PeerCertificates[0]; return nil },
	}
	cfg, err := r.ClientConfig(&tls.Config{ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handshake(t, cfg, server); err != nil || !seen.Equal(first.Cert) {
		t.Fatalf("first handshake: err=%v, presented first leaf=%v", err, seen.Equal(first.Cert))
	}
	src.set(leafMaterial(second, ca.PEM(), nil))
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := handshake(t, cfg, server); err != nil || !seen.Equal(second.Cert) {
		t.Fatalf("second handshake: err=%v, presented second leaf=%v", err, seen.Equal(second.Cert))
	}
}

// Rotate leaf, roots and client CAs on both sides mid-traffic, using the
// overlap window the way a CA rotation would, and require zero failed
// requests from valid peers over HTTP/1.1 and HTTP/2.
func TestRotationUnderLoad(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP/1.1", true: "HTTP/2"}[h2], func(t *testing.T) {
			testRotationUnderLoad(t, h2)
		})
	}
}

func testRotationUnderLoad(t *testing.T, h2 bool) {
	oldCA, newCA := testpki.NewCA(t, "old"), testpki.NewCA(t, "new")
	both := append(oldCA.PEM(), newCA.PEM()...)

	srvDir := newPKIDir(t, oldCA.Issue(t, testpki.LeafOptions{}), nil, oldCA.PEM())
	cliDir := newPKIDir(t, oldCA.Issue(t, testpki.LeafOptions{}), oldCA.PEM(), nil)
	srvFiles, cliFiles := srvDir.files, cliDir.files
	srvFiles.Roots, cliFiles.ClientCAs = "", ""
	srvR := newReloader(t, srvFiles, OverlapWindow(time.Hour))
	cliR := newReloader(t, cliFiles, OverlapWindow(time.Hour))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	srv.EnableHTTP2 = h2
	base := &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}
	if h2 {
		// NextProtos must be set on base: handshakes use configs built from
		// it, not the returned config.
		base.NextProtos = []string{"h2", "http/1.1"}
	}
	srv.TLS = srvR.ServerConfig(base)
	srv.StartTLS()
	defer srv.Close()

	var reqs, failures atomic.Int64
	var firstErr atomic.Value
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// A fresh transport per request forces a full handshake, so
				// every request exercises the current material.
				tr := &http.Transport{ForceAttemptHTTP2: h2, DisableKeepAlives: !h2}
				if err := cliR.ConfigureTransport(tr, &tls.Config{ServerName: "localhost"}); err != nil {
					panic(err)
				}
				resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(srv.URL)
				if err == nil {
					_, err = io.ReadAll(resp.Body)
					resp.Body.Close()
					if err == nil && h2 && resp.ProtoMajor != 2 {
						err = fmt.Errorf("got %s, want HTTP/2", resp.Proto)
					}
				}
				tr.CloseIdleConnections()
				reqs.Add(1)
				if err != nil {
					failures.Add(1)
					firstErr.CompareAndSwap(nil, err)
				}
			}
		}()
	}

	step := func(name string, f func()) {
		time.Sleep(50 * time.Millisecond)
		f()
		for _, r := range []*Reloader{srvR, cliR} {
			if err := r.Reload(context.Background()); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
	// 1. Both sides trust old and new.
	step("trust both", func() {
		srvDir.write(t, nil, nil, both)
		cliDir.write(t, nil, both, nil)
	})
	// 2. Leaves move to the new CA.
	step("rotate leaves", func() {
		srvDir.write(t, newCA.Issue(t, testpki.LeafOptions{}), nil, nil)
		cliDir.write(t, newCA.Issue(t, testpki.LeafOptions{}), nil, nil)
	})
	// 3. The old CA leaves the bundles; the overlap window keeps it trusted.
	step("drop old CA", func() {
		srvDir.write(t, nil, nil, newCA.PEM())
		cliDir.write(t, nil, newCA.PEM(), nil)
	})
	// 4. Another leaf rotation.
	step("rotate leaves again", func() {
		srvDir.write(t, newCA.Issue(t, testpki.LeafOptions{}), nil, nil)
		cliDir.write(t, newCA.Issue(t, testpki.LeafOptions{}), nil, nil)
	})
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	if failures.Load() != 0 {
		t.Fatalf("%d of %d requests failed; first: %v", failures.Load(), reqs.Load(), firstErr.Load())
	}
	if reqs.Load() < 20 {
		t.Fatalf("only %d requests ran", reqs.Load())
	}
	if g := srvR.Current().Generation; g < 5 {
		t.Errorf("server generation = %d, want at least 5", g)
	}
	t.Logf("%d requests, 0 failures", reqs.Load())
}

func TestServerModeChainsVerifyConnection(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	r := newReloader(t, &memSource{m: leafMaterial(ca.Issue(t, testpki.LeafOptions{}), nil, ca.PEM())})
	var calls atomic.Int32
	srvCfg := r.ServerConfig(&tls.Config{
		ClientAuth:       tls.RequireAndVerifyClientCert,
		VerifyConnection: func(tls.ConnectionState) error { calls.Add(1); return errors.New("denied by policy") },
	})
	client := &tls.Config{ServerName: "localhost", RootCAs: pool(ca.Cert), Certificates: []tls.Certificate{ca.Issue(t, testpki.LeafOptions{}).TLS(t)}}
	if _, err := handshake(t, client, srvCfg); err == nil {
		t.Error("caller's VerifyConnection did not run")
	}
	if calls.Load() != 1 {
		t.Errorf("VerifyConnection calls = %d, want 1", calls.Load())
	}
}
