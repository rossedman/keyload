package keyload

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Trigger names what started a reload.
type Trigger string

// The triggers that can start a reload.
const (
	TriggerInitial Trigger = "initial"
	TriggerManual  Trigger = "manual"
	TriggerWatch   Trigger = "watch"
	TriggerSignal  Trigger = "signal"
	TriggerTimer   Trigger = "timer"
	TriggerOverlap Trigger = "overlap" // an outgoing CA's overlap window ended
)

// Event reports a reload that changed the snapshot or failed.
type Event struct {
	Time       time.Time
	Trigger    Trigger
	Result     Result
	Generation uint64 // the new generation on success, the one still in service on failure
	Err        error  // a *ReloadError on failure

	// Certificates added to or removed from the snapshot, on success.
	Added, Removed []CertInfo
}

// Reloader keeps the current [Snapshot] and replaces it when the source
// changes. It is safe for concurrent use.
type Reloader struct {
	src  Source
	opts options
	cur  atomic.Pointer[Snapshot]

	mu               sync.Mutex // serializes reloads; guards the fields below
	retiredRoots     map[[32]byte]retiredCert
	retiredClientCAs map[[32]byte]retiredCert
	overlapTimer     *time.Timer

	stats stats

	triggers  chan Trigger
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

type retiredCert struct {
	cert  *x509.Certificate
	until time.Time
}

// New loads material from src, validates it and starts watching for changes,
// until [Reloader.Close]. It returns an error if the first load is invalid,
// so a service with bad material fails at startup rather than serving it.
//
//	r, err := keyload.New(keyload.Files{Cert: "tls.crt", Key: "tls.key", Roots: "ca.crt"})
func New(src Source, opts ...Option) (*Reloader, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	r := &Reloader{
		src:              src,
		opts:             o,
		retiredRoots:     map[[32]byte]retiredCert{},
		retiredClientCAs: map[[32]byte]retiredCert{},
		triggers:         make(chan Trigger, 1),
	}
	if err := r.reload(context.Background(), TriggerInitial); err != nil {
		return nil, err
	}

	bg, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.goFunc(func() { r.loop(bg) })
	if w, ok := src.(Watcher); ok && !o.noWatch {
		r.goFunc(func() { w.Watch(bg, func() { r.trigger(TriggerWatch) }) })
	}
	if len(o.signals) > 0 {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, o.signals...)
		r.goFunc(func() {
			defer signal.Stop(ch)
			for {
				select {
				case <-bg.Done():
					return
				case <-ch:
					r.trigger(TriggerSignal)
				}
			}
		})
	}
	if o.pollEvery > 0 {
		r.goFunc(func() {
			t := time.NewTicker(o.pollEvery)
			defer t.Stop()
			for {
				select {
				case <-bg.Done():
					return
				case <-t.C:
					r.trigger(TriggerTimer)
				}
			}
		})
	}
	return r, nil
}

// goFunc runs f in a goroutine that Close waits for.
func (r *Reloader) goFunc(f func()) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		f()
	}()
}

// Current returns the snapshot in service. It never returns nil.
func (r *Reloader) Current() *Snapshot { return r.cur.Load() }

// Reload loads, validates and swaps in new material now. On failure the
// current snapshot stays in service and the returned error is a
// *[ReloadError]. Reloading unchanged material is a no-op.
func (r *Reloader) Reload(ctx context.Context) error { return r.reload(ctx, TriggerManual) }

// Close stops watching for changes. The current snapshot stays usable.
func (r *Reloader) Close() error {
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		r.wg.Wait()
		r.mu.Lock()
		if r.overlapTimer != nil {
			r.overlapTimer.Stop()
		}
		r.mu.Unlock()
	})
	return nil
}

// trigger queues a reload without blocking; if one is already queued, t is
// dropped.
func (r *Reloader) trigger(t Trigger) {
	select {
	case r.triggers <- t:
	default: // a reload is already pending; it will see the latest material
	}
}

// loop runs queued reloads until ctx is done.
func (r *Reloader) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-r.triggers:
			_ = r.reload(ctx, t)
		}
	}
}

// reload reads and validates the material, retrying briefly while the files
// may be mid-write, and swaps in a new snapshot if it is good and has
// changed. It emits an event for a change, or for a failure once a snapshot
// exists, and returns the failure, if any.
func (r *Reloader) reload(ctx context.Context, trigger Trigger) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Outgoing CAs leave the pools when their window ends, whatever is on
	// disk: a bad file must not keep an old CA trusted.
	r.expireOverlap()

	var (
		next *Snapshot
		rr   map[[32]byte]retiredCert
		rc   map[[32]byte]retiredCert
		err  error
	)
	for attempt := 0; ; attempt++ {
		var m *Material
		m, err = r.src.Load(ctx)
		if err != nil {
			var re *ReloadError
			if !errors.As(err, &re) {
				err = &ReloadError{Result: ResultReadError, Err: err}
			}
		} else {
			next, rr, rc, err = r.build(m)
		}
		// Files may be mid-write (a new certificate next to the old key, a
		// truncated bundle), so give the writer a moment and try again.
		if err == nil || !mayBeMidWrite(err) || attempt >= r.opts.retries || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(r.opts.retryDelay << attempt):
		}
	}

	prev := r.cur.Load()
	if err != nil {
		var re *ReloadError
		if !errors.As(err, &re) {
			re = &ReloadError{Result: ResultReadError, Err: err}
			err = re
		}
		r.stats.recordFailure(re.Result)
		if prev != nil {
			r.emit(Event{Time: r.opts.now(), Trigger: trigger, Result: re.Result, Generation: prev.Generation, Err: err})
		}
		return err
	}
	if next == nil { // unchanged
		return nil
	}

	if prev != nil {
		next.Generation = prev.Generation + 1
	} else {
		next.Generation = 1
	}
	r.cur.Store(next)
	r.retiredRoots, r.retiredClientCAs = rr, rc
	r.scheduleOverlapExpiry()
	r.stats.recordSuccess(next)

	ev := Event{Time: next.LoadedAt, Trigger: trigger, Result: ResultSuccess, Generation: next.Generation}
	ev.Added, ev.Removed = diffSnapshots(prev, next)
	r.emit(ev)
	return nil
}

// mayBeMidWrite reports whether err could come from files caught in the
// middle of being written, and so is worth retrying. Validity-window errors
// can't change by waiting.
func mayBeMidWrite(err error) bool {
	return !errors.Is(err, ErrExpired) && !errors.Is(err, ErrNotYetValid) && !errors.Is(err, ErrExpiresTooSoon)
}

// expireOverlap drops retired CAs whose overlap window has ended from the
// snapshot in service. Called with r.mu held.
func (r *Reloader) expireOverlap() {
	prev := r.cur.Load()
	if prev == nil {
		return
	}
	now := r.opts.now()
	rr, rc := pruneRetired(r.retiredRoots, now), pruneRetired(r.retiredClientCAs, now)
	if len(rr) == len(r.retiredRoots) && len(rc) == len(r.retiredClientCAs) {
		return
	}
	next := *prev
	next.Generation = prev.Generation + 1
	next.LoadedAt = now
	next.Roots, next.RootCerts = buildPool(prev.rootBundle, rr)
	next.ClientCAs, next.ClientCACerts = buildPool(prev.clientCABundle, rc)
	r.cur.Store(&next)
	r.retiredRoots, r.retiredClientCAs = rr, rc
	r.scheduleOverlapExpiry()
	r.stats.recordSuccess(&next)

	ev := Event{Time: now, Trigger: TriggerOverlap, Result: ResultSuccess, Generation: next.Generation}
	ev.Added, ev.Removed = diffSnapshots(prev, &next)
	r.emit(ev)
}

// emit passes ev to every OnReload callback.
func (r *Reloader) emit(ev Event) {
	for _, fn := range r.opts.onReload {
		fn(ev)
	}
}

// build validates m and returns the snapshot it produces, or nil if it
// would be identical to the current one.
func (r *Reloader) build(m *Material) (*Snapshot, map[[32]byte]retiredCert, map[[32]byte]retiredCert, error) {
	now := r.opts.now()
	prev := r.cur.Load()
	digest := materialDigest(m)

	if prev != nil && prev.digest == digest {
		return nil, nil, nil, nil // unchanged; expireOverlap already ran
	}

	p, err := parseMaterial(m, buildOptions{now: now, minRemaining: r.opts.minRemaining})
	if err != nil {
		return nil, nil, nil, err
	}

	s := &Snapshot{
		LoadedAt:       now,
		digest:         digest,
		rootBundle:     p.roots,
		clientCABundle: p.clientCAs,
		Certificate:    p.cert,
		NotAfter:       p.notAfter,
	}
	var prevRoots, prevClientCAs []*x509.Certificate
	if prev != nil {
		prevRoots, prevClientCAs = prev.rootBundle, prev.clientCABundle
	}
	rr := overlap(prevRoots, p.roots, r.retiredRoots, now, r.opts.overlap)
	rc := overlap(prevClientCAs, p.clientCAs, r.retiredClientCAs, now, r.opts.overlap)
	s.Roots, s.RootCerts = buildPool(p.roots, rr)
	s.ClientCAs, s.ClientCACerts = buildPool(p.clientCAs, rc)

	if r.opts.requireChain && p.cert != nil {
		pool := s.Roots
		if pool == nil {
			pool = s.ClientCAs
		}
		if pool == nil {
			return nil, nil, nil, invalid(RoleLeaf, m.CertOrigin, errors.New("RequireChain is set but no roots or client CAs are configured"))
		}
		if err := verifyChain(p, pool, now); err != nil {
			return nil, nil, nil, invalid(RoleLeaf, m.CertOrigin, err)
		}
	}
	return s, rr, rc, nil
}

// pruneRetired returns the retired certificates whose overlap window has
// not ended at now.
func pruneRetired(retired map[[32]byte]retiredCert, now time.Time) map[[32]byte]retiredCert {
	out := make(map[[32]byte]retiredCert, len(retired))
	for k, v := range retired {
		if now.Before(v.until) {
			out[k] = v
		}
	}
	return out
}

// overlap returns the retired CA set after moving from prev to next: CAs that
// left the bundle are kept until now+window, and CAs that came back are no
// longer retired.
func overlap(prev, next []*x509.Certificate, retired map[[32]byte]retiredCert, now time.Time, window time.Duration) map[[32]byte]retiredCert {
	out := pruneRetired(retired, now)
	inNext := make(map[[32]byte]bool, len(next))
	for _, c := range next {
		k := certKey(c)
		inNext[k] = true
		delete(out, k)
	}
	if window <= 0 || next == nil {
		return out
	}
	for _, c := range prev {
		k := certKey(c)
		if _, ok := out[k]; !ok && !inNext[k] {
			out[k] = retiredCert{cert: c, until: now.Add(window)}
		}
	}
	return out
}

// buildPool returns a pool of the bundle plus the retired certificates still
// in their overlap window, and the certificates it holds. It returns nil for
// a nil bundle.
func buildPool(bundle []*x509.Certificate, retired map[[32]byte]retiredCert) (*x509.CertPool, []*x509.Certificate) {
	if bundle == nil {
		return nil, nil
	}
	certs := append([]*x509.Certificate(nil), bundle...)
	extra := make([]*x509.Certificate, 0, len(retired))
	for _, v := range retired {
		extra = append(extra, v.cert)
	}
	sort.Slice(extra, func(i, j int) bool { return string(extra[i].Raw) < string(extra[j].Raw) })
	certs = append(certs, extra...)
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, certs
}

// scheduleOverlapExpiry arranges a reload when the next retired CA's overlap
// window ends, so it leaves the pool on time. Called with r.mu held.
func (r *Reloader) scheduleOverlapExpiry() {
	if r.overlapTimer != nil {
		r.overlapTimer.Stop()
		r.overlapTimer = nil
	}
	var next time.Time
	for _, m := range []map[[32]byte]retiredCert{r.retiredRoots, r.retiredClientCAs} {
		for _, v := range m {
			if next.IsZero() || v.until.Before(next) {
				next = v.until
			}
		}
	}
	if next.IsZero() {
		return
	}
	d := next.Sub(r.opts.now()) + time.Millisecond
	r.overlapTimer = time.AfterFunc(d, func() { r.trigger(TriggerOverlap) })
}

// diffSnapshots returns the certificates in next but not prev, and those in
// prev but not next, sorted.
func diffSnapshots(prev, next *Snapshot) (added, removed []CertInfo) {
	type entry struct {
		role Role
		cert *x509.Certificate
	}
	collect := func(s *Snapshot) map[[32]byte]entry {
		m := map[[32]byte]entry{}
		if s == nil {
			return m
		}
		if s.Certificate != nil && s.Certificate.Leaf != nil {
			m[certKey(s.Certificate.Leaf)] = entry{RoleLeaf, s.Certificate.Leaf}
		}
		for _, c := range s.RootCerts {
			k := certKey(c)
			k[0] ^= 1 // keep roles apart when the same CA is in both pools
			m[k] = entry{RoleRoots, c}
		}
		for _, c := range s.ClientCACerts {
			k := certKey(c)
			k[0] ^= 2
			m[k] = entry{RoleClientCAs, c}
		}
		return m
	}
	a, b := collect(prev), collect(next)
	for k, e := range b {
		if _, ok := a[k]; !ok {
			added = append(added, certInfo(e.role, e.cert))
		}
	}
	for k, e := range a {
		if _, ok := b[k]; !ok {
			removed = append(removed, certInfo(e.role, e.cert))
		}
	}
	sortInfos(added)
	sortInfos(removed)
	return added, removed
}

// sortInfos sorts s by role, subject and serial.
func sortInfos(s []CertInfo) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].Role != s[j].Role {
			return s[i].Role < s[j].Role
		}
		if s[i].Subject != s[j].Subject {
			return s[i].Subject < s[j].Subject
		}
		return s[i].Serial < s[j].Serial
	})
}
