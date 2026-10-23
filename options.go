package keyload

import (
	"os"
	"time"
)

// Option configures a [Reloader].
type Option func(*options)

type options struct {
	minRemaining time.Duration
	requireChain bool
	overlap      time.Duration
	signals      []os.Signal
	pollEvery    time.Duration
	onReload     []func(Event)
	noWatch      bool
	name         string

	// For tests.
	now        func() time.Time
	retries    int
	retryDelay time.Duration
}

// defaultOptions returns the options used before any Option is applied.
func defaultOptions() options {
	return options{now: time.Now, retries: 3, retryDelay: 100 * time.Millisecond}
}

// MinRemaining rejects a leaf certificate, or any certificate in its chain,
// that expires sooner than d from the time of the reload.
func MinRemaining(d time.Duration) Option { return func(o *options) { o.minRemaining = d } }

// RequireChain rejects a leaf that does not chain to the newly loaded roots
// (or to the client CAs when no roots are configured). It catches a
// mismatched certificate and CA bundle before peers do.
func RequireChain() Option { return func(o *options) { o.requireChain = true } }

// OverlapWindow keeps CA certificates that disappear from a bundle in the
// pool for d after they were removed, so peers with certificates issued by
// the outgoing CA keep working while they rotate. It applies to both roots
// and client CAs. The default is no overlap.
func OverlapWindow(d time.Duration) Option { return func(o *options) { o.overlap = d } }

// OnSignal reloads when the process receives sig, such as syscall.SIGHUP.
// It can be given more than once.
func OnSignal(sig os.Signal) Option { return func(o *options) { o.signals = append(o.signals, sig) } }

// PollEvery reloads every d, in addition to any other trigger.
func PollEvery(d time.Duration) Option { return func(o *options) { o.pollEvery = d } }

// OnReload calls fn after every reload attempt that changed the snapshot or
// failed. Reloads of unchanged material do not produce events. fn is called
// synchronously, in order, and must not call [Reloader.Reload]. It can be
// given more than once.
func OnReload(fn func(Event)) Option { return func(o *options) { o.onReload = append(o.onReload, fn) } }

// DisableWatch stops the Reloader from using the source's [Watcher], leaving
// reloads to signals, timers and manual calls.
func DisableWatch() Option { return func(o *options) { o.noWatch = true } }

// Name labels this Reloader's metrics with reloader="name", for processes
// that run more than one.
func Name(name string) Option { return func(o *options) { o.name = name } }
