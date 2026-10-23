package grpccreds_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rossedman/keyload"
	"github.com/rossedman/keyload/grpccreds"
	"github.com/rossedman/keyload/internal/testpki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// serverNameOverrider is the deprecated credentials method, reached through a
// local interface so the tests exercise it without depending on the
// deprecated declaration.
type serverNameOverrider interface {
	OverrideServerName(string) error
}

type result struct {
	conn net.Conn
	info credentials.AuthInfo
	err  error
}

// tcpPair returns both ends of a loopback TCP connection. Unlike net.Pipe,
// it buffers writes, so a peer that stops reading cannot stall the other.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, ok := <-accepted
	if !ok {
		_ = client.Close()
		t.Fatal("accept failed")
	}
	return client, server
}

// handshake runs a client and a server handshake against each other over a
// loopback connection and returns both results.
func handshake(t *testing.T, cli, srv credentials.TransportCredentials, authority string) (c, s result) {
	t.Helper()
	cc, sc := tcpPair(t)
	t.Cleanup(func() {
		_ = cc.Close()
		_ = sc.Close()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		conn, info, err := srv.ServerHandshake(sc)
		if err != nil {
			// Unblock the client, which may be waiting on the server.
			_ = sc.Close()
		}
		done <- result{conn, info, err}
	}()
	conn, info, err := cli.ClientHandshake(ctx, authority, cc)
	if err != nil {
		_ = cc.Close()
	} else {
		// In TLS 1.3 the client finishes first; keep reading so the server
		// can deliver session tickets or a rejection alert. The read ends
		// when the connection is closed.
		go func() { _, _ = io.Copy(io.Discard, conn) }()
	}
	c = result{conn, info, err}
	s = <-done
	// The cleanup above closes the raw connections.
	return c, s
}

func peerLeaf(t *testing.T, info credentials.AuthInfo) *x509.Certificate {
	t.Helper()
	ti, ok := info.(credentials.TLSInfo)
	if !ok {
		t.Fatalf("AuthInfo is %T, want credentials.TLSInfo", info)
	}
	if len(ti.State.PeerCertificates) == 0 {
		return nil
	}
	return ti.State.PeerCertificates[0]
}

func reload(t *testing.T, r *keyload.Reloader, src *source, m keyload.Material) {
	t.Helper()
	src.set(m)
	if err := r.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestHandshake(t *testing.T) {
	t.Parallel()
	ca, other := testpki.NewCA(t, "ca"), testpki.NewCA(t, "other")
	srvLeaf := ca.Issue(t, testpki.LeafOptions{CommonName: "server"})
	cliLeaf := ca.Issue(t, testpki.LeafOptions{CommonName: "client"})
	requireClient := grpccreds.WithTLSConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert})

	tests := []struct {
		name      string
		srv       keyload.Material
		srvOpts   []grpccreds.Option
		cli       keyload.Material
		authority string
		wantErr   bool
		wantPeer  string // server's view of the client CN; "" for none
	}{
		{
			name:      "mutual TLS",
			srv:       material(srvLeaf, nil, ca.PEM()),
			srvOpts:   []grpccreds.Option{requireClient},
			cli:       material(cliLeaf, ca.PEM(), nil),
			authority: "localhost:443",
			wantPeer:  "client",
		},
		{
			name:      "server-only TLS without client leaf",
			srv:       material(srvLeaf, nil, nil),
			cli:       keyload.Material{Roots: ca.PEM()},
			authority: "localhost",
		},
		{
			name:      "client does not trust server CA",
			srv:       material(srvLeaf, nil, ca.PEM()),
			srvOpts:   []grpccreds.Option{requireClient},
			cli:       material(cliLeaf, other.PEM(), nil),
			authority: "localhost:443",
			wantErr:   true,
		},
		{
			name:      "server does not trust client CA",
			srv:       material(srvLeaf, nil, other.PEM()),
			srvOpts:   []grpccreds.Option{requireClient},
			cli:       material(cliLeaf, ca.PEM(), nil),
			authority: "localhost:443",
			wantErr:   true,
		},
		{
			name:      "client presents no certificate but one is required",
			srv:       material(srvLeaf, nil, ca.PEM()),
			srvOpts:   []grpccreds.Option{requireClient},
			cli:       keyload.Material{Roots: ca.PEM()},
			authority: "localhost:443",
			wantErr:   true,
		},
		{
			name:      "authority not in server certificate",
			srv:       material(srvLeaf, nil, nil),
			cli:       keyload.Material{Roots: ca.PEM()},
			authority: "elsewhere.test:443",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := grpccreds.New(newReloader(t, &source{m: tt.srv}), tt.srvOpts...)
			cli := grpccreds.New(newReloader(t, &source{m: tt.cli}))
			c, s := handshake(t, cli, srv, tt.authority)
			if tt.wantErr {
				if c.err == nil && s.err == nil {
					t.Fatal("handshake succeeded, want an error")
				}
				if errors.Is(c.err, context.DeadlineExceeded) {
					t.Fatalf("client timed out instead of failing verification: %v", c.err)
				}
				if c.err != nil && (c.conn != nil || c.info != nil) {
					t.Errorf("client returned conn %v and info %v with error %v", c.conn, c.info, c.err)
				}
				if s.err != nil && (s.conn != nil || s.info != nil) {
					t.Errorf("server returned conn %v and info %v with error %v", s.conn, s.info, s.err)
				}
				return
			}
			if c.err != nil || s.err != nil {
				t.Fatalf("client err = %v, server err = %v", c.err, s.err)
			}
			if got := peerLeaf(t, c.info); got == nil || got.Subject.CommonName != "server" {
				t.Errorf("client saw server leaf %v, want CN server", got)
			}
			got := peerLeaf(t, s.info)
			switch {
			case tt.wantPeer == "" && got != nil:
				t.Errorf("server saw client leaf CN %q, want none", got.Subject.CommonName)
			case tt.wantPeer != "" && (got == nil || got.Subject.CommonName != tt.wantPeer):
				t.Errorf("server saw client leaf %v, want CN %q", got, tt.wantPeer)
			}
			if c.info.AuthType() != "tls" || s.info.AuthType() != "tls" {
				t.Errorf("AuthType = %q/%q, want tls", c.info.AuthType(), s.info.AuthType())
			}
		})
	}
}

// New handshakes pick up reloaded material on both sides.
func TestHandshakeFollowsReload(t *testing.T) {
	t.Parallel()
	ca := testpki.NewCA(t, "ca")
	srvSrc := &source{m: material(ca.Issue(t, testpki.LeafOptions{CommonName: "srv1"}), nil, ca.PEM())}
	cliSrc := &source{m: material(ca.Issue(t, testpki.LeafOptions{CommonName: "cli1"}), ca.PEM(), nil)}
	srvR, cliR := newReloader(t, srvSrc), newReloader(t, cliSrc)
	srv := grpccreds.New(srvR, grpccreds.WithTLSConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}))
	cli := grpccreds.New(cliR)

	want := func(srvCN, cliCN string) {
		t.Helper()
		c, s := handshake(t, cli, srv, "localhost")
		if c.err != nil || s.err != nil {
			t.Fatalf("client err = %v, server err = %v", c.err, s.err)
		}
		if got := peerLeaf(t, c.info).Subject.CommonName; got != srvCN {
			t.Errorf("client saw server %q, want %q", got, srvCN)
		}
		if got := peerLeaf(t, s.info).Subject.CommonName; got != cliCN {
			t.Errorf("server saw client %q, want %q", got, cliCN)
		}
	}

	want("srv1", "cli1")
	want("srv1", "cli1") // served from the per-generation cache
	reload(t, srvR, srvSrc, material(ca.Issue(t, testpki.LeafOptions{CommonName: "srv2"}), nil, ca.PEM()))
	want("srv2", "cli1")
	reload(t, cliR, cliSrc, material(ca.Issue(t, testpki.LeafOptions{CommonName: "cli2"}), ca.PEM(), nil))
	want("srv2", "cli2")
}

// Handshakes within one generation share a server config, so sessions
// resume; a reload builds a new config whose ticket keys reject old tickets.
func TestSessionResumptionPerGeneration(t *testing.T) {
	t.Parallel()
	ca := testpki.NewCA(t, "ca")
	srvSrc := &source{m: material(ca.Issue(t, testpki.LeafOptions{}), nil, nil)}
	srvR := newReloader(t, srvSrc)
	srv := grpccreds.New(srvR)
	cli := grpccreds.New(newReloader(t, &source{m: keyload.Material{Roots: ca.PEM()}}),
		grpccreds.WithTLSConfig(&tls.Config{
			MaxVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(8),
		}))

	resumed := func() bool {
		t.Helper()
		c, s := handshake(t, cli, srv, "localhost")
		if c.err != nil || s.err != nil {
			t.Fatalf("client err = %v, server err = %v", c.err, s.err)
		}
		return c.info.(credentials.TLSInfo).State.DidResume
	}

	if resumed() {
		t.Fatal("first handshake resumed")
	}
	if !resumed() {
		t.Fatal("second handshake in the same generation did not resume")
	}
	reload(t, srvR, srvSrc, material(ca.Issue(t, testpki.LeafOptions{}), nil, nil))
	if resumed() {
		t.Fatal("handshake after reload resumed a session from the old generation")
	}
	if !resumed() {
		t.Fatal("second handshake after reload did not resume")
	}
}

// Concurrent first handshakes in a generation all succeed and race on the
// cache safely.
func TestConcurrentHandshakes(t *testing.T) {
	t.Parallel()
	ca := testpki.NewCA(t, "ca")
	srvSrc := &source{m: material(ca.Issue(t, testpki.LeafOptions{}), nil, nil)}
	srvR := newReloader(t, srvSrc)
	srv := grpccreds.New(srvR)
	cli := grpccreds.New(newReloader(t, &source{m: keyload.Material{Roots: ca.PEM()}}))

	for range 3 {
		var wg sync.WaitGroup
		errs := make(chan error, 32)
		for range cap(errs) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cc, sc := net.Pipe()
				defer func() { _ = cc.Close() }()
				go func() {
					_, _, _ = srv.ServerHandshake(sc)
					_ = sc.Close()
				}()
				_, _, err := cli.ClientHandshake(t.Context(), "localhost", cc)
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		reload(t, srvR, srvSrc, material(ca.Issue(t, testpki.LeafOptions{}), nil, nil))
	}
}

func TestClientHandshakeContextCanceled(t *testing.T) {
	t.Parallel()
	ca := testpki.NewCA(t, "ca")
	cli := grpccreds.New(newReloader(t, &source{m: keyload.Material{Roots: ca.PEM()}}))
	cc, sc := net.Pipe()
	defer func() { _ = sc.Close() }()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// Nobody serves the other end, so only the context can end the handshake.
	conn, info, err := cli.ClientHandshake(ctx, "localhost", cc)
	if err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if conn != nil || info != nil {
		t.Errorf("got conn %v, info %v on error", conn, info)
	}
}

func TestInfo(t *testing.T) {
	t.Parallel()
	ca := testpki.NewCA(t, "ca")
	r := newReloader(t, &source{m: material(ca.Issue(t, testpki.LeafOptions{}), ca.PEM(), nil)})
	for _, c := range []credentials.TransportCredentials{
		grpccreds.New(r),
		grpccreds.New(r, grpccreds.WithTLSConfig(&tls.Config{ServerName: "x.test"})),
		grpccreds.New(r).Clone(),
	} {
		if got := c.Info().SecurityProtocol; got != "tls" {
			t.Errorf("SecurityProtocol = %q, want tls", got)
		}
	}
}

// serverNameServer starts a gRPC server whose leaf is valid only for
// server.test, so a client dialing 127.0.0.1 must override the server name.
func serverNameServer(t *testing.T) (addr string, roots []byte) {
	t.Helper()
	ca := testpki.NewCA(t, "ca")
	leaf := ca.Issue(t, testpki.LeafOptions{DNSNames: []string{"server.test"}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer(grpc.Creds(grpccreds.New(newReloader(t, &source{m: material(leaf, nil, nil)}))))
	healthpb.RegisterHealthServer(s, health.NewServer())
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(s.Stop)
	return ln.Addr().String(), ca.PEM()
}

func call(t *testing.T, addr string, c credentials.TransportCredentials) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(c))
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()
	_, err = healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{}, grpc.WaitForReady(false))
	return err
}

func TestServerNameFromBaseConfig(t *testing.T) {
	t.Parallel()
	addr, roots := serverNameServer(t)
	r := newReloader(t, &source{m: keyload.Material{Roots: roots}})

	if err := call(t, addr, grpccreds.New(r)); err == nil {
		t.Fatal("call to 127.0.0.1 verified a certificate only valid for server.test")
	}
	if err := call(t, addr, grpccreds.New(r, grpccreds.WithTLSConfig(&tls.Config{ServerName: "server.test"}))); err != nil {
		t.Fatalf("with ServerName server.test: %v", err)
	}
}

// WithTLSConfig copies the base, so later changes by the caller have no
// effect.
func TestWithTLSConfigCopiesBase(t *testing.T) {
	t.Parallel()
	addr, roots := serverNameServer(t)
	r := newReloader(t, &source{m: keyload.Material{Roots: roots}})
	base := &tls.Config{ServerName: "server.test"}
	c := grpccreds.New(r, grpccreds.WithTLSConfig(base))
	base.ServerName = "wrong.test"
	if err := call(t, addr, c); err != nil {
		t.Fatalf("mutating the caller's config changed the credentials: %v", err)
	}
}

func TestOverrideServerName(t *testing.T) {
	t.Parallel()
	addr, roots := serverNameServer(t)
	r := newReloader(t, &source{m: keyload.Material{Roots: roots}})
	base := &tls.Config{ServerName: "wrong.test"}
	c := grpccreds.New(r, grpccreds.WithTLSConfig(base))

	// Prime the cache with a handshake under the old name.
	if err := call(t, addr, c); err == nil {
		t.Fatal("call with ServerName wrong.test succeeded")
	}
	if err := c.(serverNameOverrider).OverrideServerName("server.test"); err != nil {
		t.Fatalf("OverrideServerName: %v", err)
	}
	if err := call(t, addr, c); err != nil {
		t.Fatalf("after OverrideServerName: %v", err)
	}
	if base.ServerName != "wrong.test" {
		t.Errorf("OverrideServerName mutated the caller's base config: ServerName = %q", base.ServerName)
	}
}

// A clone shares the reloader but not the base config: overriding the
// clone's server name leaves the original unchanged, and vice versa.
func TestClone(t *testing.T) {
	t.Parallel()
	addr, roots := serverNameServer(t)
	r := newReloader(t, &source{m: keyload.Material{Roots: roots}})
	orig := grpccreds.New(r)

	clone := orig.Clone()
	if clone == orig {
		t.Fatal("Clone returned the receiver")
	}
	if err := clone.(serverNameOverrider).OverrideServerName("server.test"); err != nil {
		t.Fatal(err)
	}
	if err := call(t, addr, clone); err != nil {
		t.Fatalf("clone with overridden server name: %v", err)
	}
	if err := call(t, addr, orig); err == nil {
		t.Fatal("overriding the clone's server name changed the original")
	}

	// A clone of a configured credential keeps its server name.
	clone2 := clone.Clone()
	if err := clone2.(serverNameOverrider).OverrideServerName("wrong.test"); err != nil {
		t.Fatal(err)
	}
	if err := call(t, addr, clone); err != nil {
		t.Fatalf("overriding a clone's clone changed the clone: %v", err)
	}
	if err := call(t, addr, clone.Clone()); err != nil {
		t.Fatalf("clone did not keep the base server name: %v", err)
	}

	// A clone follows the same reloader: a clone taken while the roots do
	// not trust the server starts working once the reloader adds them.
	src2 := &source{m: keyload.Material{Roots: testpki.NewCA(t, "other").PEM()}}
	r2 := newReloader(t, src2)
	c2 := grpccreds.New(r2, grpccreds.WithTLSConfig(&tls.Config{ServerName: "server.test"})).Clone()
	if err := call(t, addr, c2); err == nil {
		t.Fatal("clone trusted a server its roots do not cover")
	}
	reload(t, r2, src2, keyload.Material{Roots: roots})
	if err := call(t, addr, c2); err != nil {
		t.Fatalf("clone did not follow the reloader's new roots: %v", err)
	}
}
