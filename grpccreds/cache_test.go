package grpccreds

import (
	"crypto/tls"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rossedman/keyload"
	"github.com/rossedman/keyload/internal/testpki"
)

// waitForLockWaiter waits until some goroutine is blocked acquiring a mutex
// inside (*creds).get.
func waitForLockWaiter(t *testing.T) {
	t.Helper()
	buf := make([]byte, 1<<20)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "sync.(*Mutex).Lock") && strings.Contains(g, "grpccreds.(*creds).get") {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatal("no goroutine blocked on the cache lock")
}

// TestGetWaiterUsesEntryBuiltWhileWaiting checks that a caller that missed
// the cache and then waited for the lock uses the entry the lock holder
// built, rather than building its own.
func TestGetWaiterUsesEntryBuiltWhileWaiting(t *testing.T) {
	dir := testpki.NewDir(t, t.TempDir())
	r, err := keyload.New(keyload.Files{Cert: dir.File("tls.crt"), Key: dir.File("tls.key")}, keyload.DisableWatch())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	c := New(r).(*creds)
	var builds atomic.Int32
	release := make(chan struct{})
	build := func(s *keyload.Snapshot) *tls.Config {
		builds.Add(1)
		<-release // hold the lock until the second caller is waiting
		return s.ServerConfig(nil)
	}

	first := make(chan any)
	go func() { first <- c.get(&c.cache.server, build) }()
	for builds.Load() == 0 {
		runtime.Gosched()
	}

	second := make(chan any)
	go func() { second <- c.get(&c.cache.server, build) }()
	waitForLockWaiter(t)
	close(release)

	a, b := <-first, <-second
	if a != b {
		t.Error("the waiting caller got different credentials from the lock holder")
	}
	if n := builds.Load(); n != 1 {
		t.Errorf("built %d times, want 1", n)
	}
}
