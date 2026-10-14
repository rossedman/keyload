package keyload

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

func TestNewRejectsInvalidFirstLoad(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	leaf := ca.Issue(t, testpki.LeafOptions{NotAfter: time.Now().Add(-time.Minute)})
	_, err := New(&memSource{m: leafMaterial(leaf, ca.PEM(), nil)}, fastRetries())
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("New() error = %v, want ErrExpired", err)
	}
}

func TestFirstLoad(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	leaf := ca.Issue(t, testpki.LeafOptions{})
	evs := newEvents()
	r := newReloader(t, &memSource{m: leafMaterial(leaf, ca.PEM(), ca.PEM())}, evs.option())

	s := r.Current()
	if s.Generation != 1 {
		t.Errorf("Generation = %d, want 1", s.Generation)
	}
	if !s.Certificate.Leaf.Equal(leaf.Cert) {
		t.Error("snapshot leaf is not the loaded leaf")
	}
	if !s.NotAfter.Equal(leaf.Cert.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", s.NotAfter, leaf.Cert.NotAfter)
	}
	if len(s.RootCerts) != 1 || len(s.ClientCACerts) != 1 {
		t.Errorf("got %d roots and %d client CAs, want 1 and 1", len(s.RootCerts), len(s.ClientCACerts))
	}
	ev := evs.next(t, time.Second)
	if ev.Trigger != TriggerInitial || ev.Result != ResultSuccess || len(ev.Added) != 3 {
		t.Errorf("first event = %+v", ev)
	}
}

func TestTrustOnly(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	r := newReloader(t, &memSource{m: Material{Roots: ca.PEM()}})
	if s := r.Current(); s.Certificate != nil || s.Roots == nil || s.ClientCAs != nil {
		t.Errorf("trust-only snapshot = %+v", s)
	}
}

// Every bad reload must keep the old snapshot and report why.
func TestBadReloadDrills(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	other := testpki.NewCA(t, "other")
	good := ca.Issue(t, testpki.LeafOptions{})
	otherLeaf := ca.Issue(t, testpki.LeafOptions{})

	tests := []struct {
		name   string
		mat    func() Material
		opts   []Option
		result Result
		role   Role
		is     error
	}{
		{
			name:   "truncated leaf PEM",
			mat:    func() Material { m := leafMaterial(good, ca.PEM(), nil); m.Cert = m.Cert[:len(m.Cert)/2]; return m },
			result: ResultInvalid, role: RoleLeaf, is: ErrTruncatedPEM,
		},
		{
			name:   "truncated CA bundle",
			mat:    func() Material { return leafMaterial(good, append(ca.PEM(), other.PEM()[:100]...), nil) },
			result: ResultInvalid, role: RoleRoots, is: ErrTruncatedPEM,
		},
		{
			name: "mismatched key",
			mat: func() Material {
				m := leafMaterial(good, ca.PEM(), nil)
				m.Key = otherLeaf.KeyPEM
				return m
			},
			result: ResultInvalid, role: RoleKey, is: ErrKeyMismatch,
		},
		{
			name:   "truncated key",
			mat:    func() Material { m := leafMaterial(good, ca.PEM(), nil); m.Key = m.Key[:40]; return m },
			result: ResultInvalid, role: RoleKey, is: ErrTruncatedPEM,
		},
		{
			name: "expired leaf",
			mat: func() Material {
				return leafMaterial(ca.Issue(t, testpki.LeafOptions{NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)}), ca.PEM(), nil)
			},
			result: ResultInvalid, role: RoleLeaf, is: ErrExpired,
		},
		{
			name: "not yet valid leaf",
			mat: func() Material {
				return leafMaterial(ca.Issue(t, testpki.LeafOptions{NotBefore: time.Now().Add(time.Hour)}), ca.PEM(), nil)
			},
			result: ResultInvalid, role: RoleLeaf, is: ErrNotYetValid,
		},
		{
			name: "expires too soon",
			mat: func() Material {
				return leafMaterial(ca.Issue(t, testpki.LeafOptions{NotAfter: time.Now().Add(30 * time.Minute)}), ca.PEM(), nil)
			},
			opts:   []Option{MinRemaining(time.Hour)},
			result: ResultInvalid, role: RoleLeaf, is: ErrExpiresTooSoon,
		},
		{
			name:   "empty roots bundle",
			mat:    func() Material { return leafMaterial(good, []byte{}, nil) },
			result: ResultInvalid, role: RoleRoots, is: ErrEmptyBundle,
		},
		{
			name:   "client CA bundle without certificates",
			mat:    func() Material { return leafMaterial(good, ca.PEM(), []byte("not a certificate\n")) },
			result: ResultInvalid, role: RoleClientCAs, is: ErrEmptyBundle,
		},
		{
			name:   "leaf does not chain to new roots",
			mat:    func() Material { return leafMaterial(good, other.PEM(), nil) },
			opts:   []Option{RequireChain()},
			result: ResultInvalid, role: RoleLeaf, is: ErrChainVerification,
		},
		{
			name:   "half-written rotation: new cert, old key",
			mat:    func() Material { m := leafMaterial(otherLeaf, ca.PEM(), nil); m.Key = good.KeyPEM; return m },
			result: ResultInvalid, role: RoleKey, is: ErrKeyMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &memSource{m: leafMaterial(good, ca.PEM(), ca.PEM())}
			evs := newEvents()
			r := newReloader(t, src, append(tt.opts, evs.option())...)
			before := r.Current()
			evs.drain()

			src.set(tt.mat())
			err := r.Reload(context.Background())
			var re *ReloadError
			if !errors.As(err, &re) {
				t.Fatalf("Reload() error = %v, want *ReloadError", err)
			}
			if re.Result != tt.result || re.Role != tt.role || !errors.Is(err, tt.is) {
				t.Errorf("Reload() error = %+v (%v), want result %s role %s is %v", re, err, tt.result, tt.role, tt.is)
			}
			if r.Current() != before {
				t.Error("snapshot changed after a bad reload")
			}
			ev := evs.next(t, time.Second)
			if ev.Result != tt.result || ev.Generation != before.Generation || ev.Err == nil {
				t.Errorf("event = %+v", ev)
			}
			if got := r.Stats().Invalid; got != 1 {
				t.Errorf("Stats().Invalid = %d, want 1", got)
			}
		})
	}
}

func TestReadErrorKeepsSnapshot(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	d := newPKIDir(t, ca.Issue(t, testpki.LeafOptions{}), ca.PEM(), ca.PEM())
	r := newReloader(t, d.files, DisableWatch())
	before := r.Current()

	if err := os.Remove(d.files.Key); err != nil {
		t.Fatal(err)
	}
	err := r.Reload(context.Background())
	var re *ReloadError
	if !errors.As(err, &re) || re.Result != ResultReadError || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Reload() error = %v, want read_error wrapping ErrNotExist", err)
	}
	if r.Current() != before {
		t.Error("snapshot changed after a failed read")
	}
	if st := r.Stats(); st.ReadError != 1 || st.Success != 1 {
		t.Errorf("Stats() = %+v", st)
	}
}

func TestUnchangedReloadIsNoop(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	evs := newEvents()
	r := newReloader(t, &memSource{m: leafMaterial(ca.Issue(t, testpki.LeafOptions{}), ca.PEM(), nil)}, evs.option())
	evs.drain()
	before := r.Current()
	for i := 0; i < 3; i++ {
		if err := r.Reload(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if r.Current() != before {
		t.Error("unchanged reload swapped the snapshot")
	}
	select {
	case ev := <-evs.ch:
		t.Errorf("unexpected event %+v", ev)
	default:
	}
}

// A reload that sees files mid-write retries and succeeds once the writer
// finishes.
func TestRetryRecoversFromMidWrite(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	old, next := ca.Issue(t, testpki.LeafOptions{}), ca.Issue(t, testpki.LeafOptions{})
	src := &memSource{m: leafMaterial(old, ca.PEM(), nil)}
	r := newReloader(t, src)

	src.mu.Lock()
	src.n = 0
	src.hook = func(n int) (*Material, error) {
		switch n {
		case 1: // new certificate, old key
			m := leafMaterial(next, ca.PEM(), nil)
			m.Key = old.KeyPEM
			return &m, nil
		case 2:
			return nil, os.ErrNotExist
		default:
			m := leafMaterial(next, ca.PEM(), nil)
			return &m, nil
		}
	}
	src.mu.Unlock()

	if err := r.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() = %v, want success after retries", err)
	}
	if !r.Current().Certificate.Leaf.Equal(next.Cert) {
		t.Error("new leaf not in service")
	}
	if src.n != 3 {
		t.Errorf("source loaded %d times, want 3", src.n)
	}
}

// Validity errors can't be fixed by waiting, so they fail without retrying;
// errors a half-finished write could cause are retried.
func TestRetriesOnlyWhatAWriterCouldFix(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	good := ca.Issue(t, testpki.LeafOptions{})
	expired := ca.Issue(t, testpki.LeafOptions{NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})
	mismatched := leafMaterial(good, ca.PEM(), nil)
	mismatched.Key = ca.Issue(t, testpki.LeafOptions{}).KeyPEM

	for _, tt := range []struct {
		name  string
		m     Material
		loads int
	}{
		{"expired", leafMaterial(expired, ca.PEM(), nil), 1},
		{"key mismatch", mismatched, 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := &memSource{m: leafMaterial(good, ca.PEM(), nil)}
			r := newReloader(t, src)
			src.mu.Lock()
			src.n = 0
			src.mu.Unlock()
			src.set(tt.m)
			if err := r.Reload(context.Background()); err == nil {
				t.Fatal("bad material accepted")
			}
			if src.n != tt.loads {
				t.Errorf("source loaded %d times, want %d", src.n, tt.loads)
			}
		})
	}
}

func TestEventDiff(t *testing.T) {
	ca, ca2 := testpki.NewCA(t, "ca"), testpki.NewCA(t, "ca2")
	old, next := ca.Issue(t, testpki.LeafOptions{}), ca2.Issue(t, testpki.LeafOptions{})
	src := &memSource{m: leafMaterial(old, ca.PEM(), nil)}
	evs := newEvents()
	r := newReloader(t, src, evs.option())
	evs.drain()

	src.set(leafMaterial(next, ca2.PEM(), nil))
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	ev := evs.next(t, time.Second)
	if ev.Generation != 2 || ev.Trigger != TriggerManual {
		t.Errorf("event = %+v", ev)
	}
	roles := func(infos []CertInfo) string {
		var s []string
		for _, i := range infos {
			s = append(s, string(i.Role)+":"+i.Subject)
		}
		return strings.Join(s, ",")
	}
	if got, want := roles(ev.Added), "leaf:CN=leaf,roots:CN=ca2"; got != want {
		t.Errorf("Added = %s, want %s", got, want)
	}
	if got, want := roles(ev.Removed), "leaf:CN=leaf,roots:CN=ca"; got != want {
		t.Errorf("Removed = %s, want %s", got, want)
	}
	if ev.Added[0].Serial == ev.Removed[0].Serial {
		t.Error("leaf serials should differ")
	}
}

func TestOverlapWindow(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	oldCA, newCA := testpki.NewCA(t, "old"), testpki.NewCA(t, "new")
	leaf := oldCA.Issue(t, testpki.LeafOptions{})
	src := &memSource{m: leafMaterial(leaf, oldCA.PEM(), oldCA.PEM())}
	evs := newEvents()
	r := newReloader(t, src, OverlapWindow(time.Hour), withClock(clock.Now), evs.option())

	src.set(leafMaterial(leaf, newCA.PEM(), newCA.PEM()))
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := r.Current()
	if len(s.RootCerts) != 2 || len(s.ClientCACerts) != 2 {
		t.Fatalf("during overlap got %d roots, %d client CAs; want 2 and 2", len(s.RootCerts), len(s.ClientCACerts))
	}
	if !s.RootCerts[0].Equal(newCA.Cert) || !s.RootCerts[1].Equal(oldCA.Cert) {
		t.Error("pool should hold the new CA first, then the outgoing one")
	}

	// Unchanged material inside the window is a no-op.
	clock.Add(30 * time.Minute)
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Current() != s {
		t.Error("reload inside the overlap window changed the snapshot")
	}

	// After the window, the outgoing CA leaves the pool.
	clock.Add(31 * time.Minute)
	evs.drain()
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	s = r.Current()
	if len(s.RootCerts) != 1 || !s.RootCerts[0].Equal(newCA.Cert) || len(s.ClientCACerts) != 1 {
		t.Fatalf("after overlap got %d roots, %d client CAs; want only the new CA", len(s.RootCerts), len(s.ClientCACerts))
	}
	ev := evs.next(t, time.Second)
	if len(ev.Removed) != 2 || ev.Removed[0].Subject != "CN=old" {
		t.Errorf("Removed = %+v, want the old CA from both pools", ev.Removed)
	}
}

func TestOverlapExpiryTriggersReload(t *testing.T) {
	oldCA, newCA := testpki.NewCA(t, "old"), testpki.NewCA(t, "new")
	src := &memSource{m: Material{Roots: oldCA.PEM()}}
	evs := newEvents()
	r := newReloader(t, src, OverlapWindow(50*time.Millisecond), evs.option())
	src.set(Material{Roots: newCA.PEM()})
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	evs.drain()
	ev := evs.next(t, 2*time.Second)
	if ev.Trigger != TriggerOverlap || len(r.Current().RootCerts) != 1 {
		t.Errorf("event = %+v, roots = %d", ev, len(r.Current().RootCerts))
	}
}

// An overlap window ends on time even when the files on disk are bad at that
// moment: keep-last-good must not keep an outgoing CA trusted.
func TestOverlapEndsWhileFilesAreInvalid(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	oldCA, newCA := testpki.NewCA(t, "old"), testpki.NewCA(t, "new")
	leaf := newCA.Issue(t, testpki.LeafOptions{})
	src := &memSource{m: leafMaterial(leaf, oldCA.PEM(), nil)}
	evs := newEvents()
	r := newReloader(t, src, OverlapWindow(time.Hour), withClock(clock.Now), evs.option())
	src.set(leafMaterial(leaf, newCA.PEM(), nil))
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	m := leafMaterial(leaf, newCA.PEM(), nil)
	m.Key = []byte("broken")
	src.set(m)
	clock.Add(2 * time.Hour)
	evs.drain()
	if err := r.Reload(context.Background()); err == nil {
		t.Fatal("broken key accepted")
	}
	s := r.Current()
	if len(s.RootCerts) != 1 || !s.RootCerts[0].Equal(newCA.Cert) {
		t.Fatalf("roots = %d certificates, want only the new CA", len(s.RootCerts))
	}
	if !s.Certificate.Leaf.Equal(leaf.Cert) {
		t.Error("leaf changed")
	}
	if ev := evs.next(t, time.Second); ev.Trigger != TriggerOverlap || len(ev.Removed) != 1 || ev.Removed[0].Subject != "CN=old" {
		t.Errorf("first event = %+v, want the old CA removed by the overlap trigger", ev)
	}
	if ev := evs.next(t, time.Second); ev.Result != ResultInvalid {
		t.Errorf("second event = %+v, want the rejected key", ev)
	}
}

func TestOverlapCARestored(t *testing.T) {
	oldCA, newCA := testpki.NewCA(t, "old"), testpki.NewCA(t, "new")
	src := &memSource{m: Material{Roots: oldCA.PEM()}}
	r := newReloader(t, src, OverlapWindow(time.Hour))
	src.set(Material{Roots: newCA.PEM()})
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	src.set(Material{Roots: oldCA.PEM()}) // roll back
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	// old is in the bundle again, new is now the outgoing CA.
	if s := r.Current(); len(s.RootCerts) != 2 || !s.RootCerts[0].Equal(oldCA.Cert) || !s.RootCerts[1].Equal(newCA.Cert) {
		t.Errorf("roots = %d, want old then new", len(s.RootCerts))
	}
}

func waitGeneration(t *testing.T, r *Reloader, gen uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for r.Current().Generation < gen {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for generation %d (at %d)", gen, r.Current().Generation)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPollFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := make(chan struct{}, 10)
	go pollFiles(ctx, 10*time.Millisecond, func() { calls <- struct{}{} })
	for i := 0; i < 2; i++ {
		select {
		case <-calls:
		case <-time.After(time.Second):
			t.Fatal("poll did not fire")
		}
	}
}

func TestPollEvery(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	src := &memSource{m: Material{Roots: ca.PEM()}}
	r := newReloader(t, src, PollEvery(10*time.Millisecond))
	src.set(Material{Roots: testpki.NewCA(t, "ca2").PEM()})
	waitGeneration(t, r, 2, 5*time.Second)
}

func TestMetrics(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	leaf := ca.Issue(t, testpki.LeafOptions{})
	src := &memSource{m: leafMaterial(leaf, ca.PEM(), nil)}
	r := newReloader(t, src, Name("edge"))
	src.set(Material{Cert: []byte("junk"), Key: leaf.KeyPEM})
	_ = r.Reload(context.Background())

	var buf bytes.Buffer
	if err := r.WriteMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`keyload_generation{reloader="edge"} 1`,
		`keyload_reload_total{reloader="edge",result="success"} 1`,
		`keyload_reload_total{reloader="edge",result="invalid"} 1`,
		`keyload_reload_total{reloader="edge",result="read_error"} 0`,
		`keyload_cert_not_after_seconds{reloader="edge",role="leaf"} `,
		`keyload_cert_not_after_seconds{reloader="edge",role="roots"} `,
		`keyload_last_success_timestamp_seconds{reloader="edge"} `,
		"# TYPE keyload_reload_total counter",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "client_cas") {
		t.Error("metrics report client CAs that are not configured")
	}
}

func TestEventsNeverContainKeyMaterial(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	leaf := ca.Issue(t, testpki.LeafOptions{})
	src := &memSource{m: leafMaterial(leaf, ca.PEM(), nil)}
	evs := newEvents()
	r := newReloader(t, src, evs.option())
	m := leafMaterial(leaf, ca.PEM(), nil)
	m.Key = []byte("-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n")
	src.set(m)
	_ = r.Reload(context.Background())
	for _, ev := range evs.all {
		if ev.Err != nil && strings.Contains(ev.Err.Error(), "c2VjcmV0") {
			t.Errorf("event error leaks key bytes: %v", ev.Err)
		}
	}
}

func TestSourceFuncAndFilesErrors(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	r := newReloader(t, SourceFunc(func(context.Context) (*Material, error) {
		return &Material{Roots: ca.PEM()}, nil
	}))
	if r.Current().Roots == nil {
		t.Error("SourceFunc material not loaded")
	}
	if _, err := New(Files{Cert: "tls.crt"}, fastRetries()); err == nil {
		t.Error("Files with Cert but no Key accepted")
	}
	if _, err := New(&memSource{m: Material{Cert: []byte("x")}}, fastRetries()); err == nil {
		t.Error("Material with Cert but no Key accepted")
	}
	if _, err := New(&memSource{m: Material{Cert: []byte{}, Key: []byte("x")}}, fastRetries()); !errors.Is(err, ErrEmptyBundle) {
		t.Errorf("empty certificate: err = %v, want ErrEmptyBundle", err)
	}
}

func TestReloadErrorMessage(t *testing.T) {
	err := &ReloadError{Result: ResultReadError, Err: os.ErrNotExist}
	if got := err.Error(); got != "keyload: read failed: file does not exist" {
		t.Errorf("Error() = %q", got)
	}
	err = &ReloadError{Result: ResultInvalid, Role: RoleKey, Origin: "/tls/tls.key", Err: ErrKeyMismatch}
	if got := err.Error(); got != "keyload: invalid material (key /tls/tls.key): private key does not match the leaf certificate" {
		t.Errorf("Error() = %q", got)
	}
}

func TestSortInfos(t *testing.T) {
	s := []CertInfo{{Role: RoleRoots, Subject: "b"}, {Role: RoleRoots, Subject: "a", Serial: "2"}, {Role: RoleLeaf}, {Role: RoleRoots, Subject: "a", Serial: "1"}}
	sortInfos(s)
	if s[0].Role != RoleLeaf || s[1].Serial != "1" || s[2].Serial != "2" || s[3].Subject != "b" {
		t.Errorf("sortInfos = %+v", s)
	}
}
