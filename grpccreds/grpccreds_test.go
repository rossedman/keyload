package grpccreds_test

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rossedman/keyload"
	"github.com/rossedman/keyload/grpccreds"
	"github.com/rossedman/keyload/internal/testpki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type source struct {
	mu sync.Mutex
	m  keyload.Material
}

func (s *source) Load(context.Context) (*keyload.Material, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.m
	return &m, nil
}

func (s *source) set(m keyload.Material) {
	s.mu.Lock()
	s.m = m
	s.mu.Unlock()
}

func material(leaf *testpki.Leaf, roots, clientCAs []byte) keyload.Material {
	return keyload.Material{Cert: leaf.CertPEM, Key: leaf.KeyPEM, Roots: roots, ClientCAs: clientCAs}
}

func newReloader(t *testing.T, src keyload.Source) *keyload.Reloader {
	t.Helper()
	r, err := keyload.New(src, keyload.OverlapWindow(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func startServer(t *testing.T, r *keyload.Reloader) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer(grpc.Creds(grpccreds.New(r, grpccreds.WithTLSConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}))))
	healthpb.RegisterHealthServer(s, health.NewServer())
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(s.Stop)
	return ln.Addr().String()
}

func check(ctx context.Context, addr string, r *keyload.Reloader) error {
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(grpccreds.New(r, grpccreds.WithTLSConfig(&tls.Config{ServerName: "localhost"}))))
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()
	_, err = healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func TestMutualTLSFollowsReloads(t *testing.T) {
	ca, ca2 := testpki.NewCA(t, "ca"), testpki.NewCA(t, "ca2")
	srvSrc := &source{m: material(ca.Issue(t, testpki.LeafOptions{}), nil, ca.PEM())}
	cliSrc := &source{m: material(ca.Issue(t, testpki.LeafOptions{}), ca.PEM(), nil)}
	srvR, cliR := newReloader(t, srvSrc), newReloader(t, cliSrc)
	addr := startServer(t, srvR)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := check(ctx, addr, cliR); err != nil {
		t.Fatal(err)
	}

	// The server moves to a leaf from ca2, which the client does not trust.
	srvSrc.set(material(ca2.Issue(t, testpki.LeafOptions{}), nil, ca.PEM()))
	if err := srvR.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	failCtx, failCancel := context.WithTimeout(ctx, time.Second)
	defer failCancel()
	if err := check(failCtx, addr, cliR); err == nil {
		t.Fatal("client accepted a server signed by an untrusted CA")
	}

	// The client reloads its roots and trusts the server again.
	cliSrc.set(material(ca.Issue(t, testpki.LeafOptions{}), ca2.PEM(), nil))
	if err := cliR.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if err := check(ctx, addr, cliR); err != nil {
		t.Fatal(err)
	}
}

// Rotate leaves and CAs on both sides while new connections are made
// continuously, and require that none fail.
func TestRotationUnderLoad(t *testing.T) {
	oldCA, newCA := testpki.NewCA(t, "old"), testpki.NewCA(t, "new")
	both := append(oldCA.PEM(), newCA.PEM()...)
	srvSrc := &source{m: material(oldCA.Issue(t, testpki.LeafOptions{}), nil, oldCA.PEM())}
	cliSrc := &source{m: material(oldCA.Issue(t, testpki.LeafOptions{}), oldCA.PEM(), nil)}
	srvR, cliR := newReloader(t, srvSrc), newReloader(t, cliSrc)
	addr := startServer(t, srvR)

	var calls, failures atomic.Int64
	var firstErr atomic.Value
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := check(ctx, addr, cliR)
				cancel()
				calls.Add(1)
				if err != nil {
					failures.Add(1)
					firstErr.CompareAndSwap(nil, err)
				}
			}
		}()
	}

	ctx := context.Background()
	step := func(srv, cli keyload.Material) {
		time.Sleep(50 * time.Millisecond)
		srvSrc.set(srv)
		cliSrc.set(cli)
		if err := srvR.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		if err := cliR.Reload(ctx); err != nil {
			t.Fatal(err)
		}
	}
	srvLeaf, cliLeaf := oldCA.Issue(t, testpki.LeafOptions{}), oldCA.Issue(t, testpki.LeafOptions{})
	step(material(srvLeaf, nil, both), material(cliLeaf, both, nil))
	srvLeaf, cliLeaf = newCA.Issue(t, testpki.LeafOptions{}), newCA.Issue(t, testpki.LeafOptions{})
	step(material(srvLeaf, nil, both), material(cliLeaf, both, nil))
	step(material(srvLeaf, nil, newCA.PEM()), material(cliLeaf, newCA.PEM(), nil))
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	if failures.Load() != 0 {
		t.Fatalf("%d of %d calls failed; first: %v", failures.Load(), calls.Load(), firstErr.Load())
	}
	if calls.Load() < 10 {
		t.Fatalf("only %d calls ran", calls.Load())
	}
	t.Logf("%d calls, 0 failures", calls.Load())
}
