//go:build linux

package keyload

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

// watchForTest makes the watch tests independent of how many inotify
// instances the machine has left. CI runners can hit the per-user limit, in
// which case Files falls back to polling, as documented; the test then polls
// quickly instead of every 30 seconds. Any other fallback is a watcher bug and
// fails the test.
func watchForTest(t *testing.T) {
	t.Helper()
	var mu sync.Mutex
	prevPoll, prevHook := pollFallback, watchFallback
	pollFallback = 50 * time.Millisecond
	watchFallback = func(reason string, err error) {
		mu.Lock()
		defer mu.Unlock()
		if reason == "init" && (errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)) {
			t.Logf("inotify unavailable (%v); testing the polling fallback instead", err)
			return
		}
		t.Errorf("watcher fell back to polling: %s %v", reason, err)
	}
	t.Cleanup(func() { pollFallback, watchFallback = prevPoll, prevHook })
}

// TestWatchFallsBackWhenInotifyIsExhausted checks that reloads still happen,
// by polling, when no inotify instance can be created.
func TestWatchFallsBackWhenInotifyIsExhausted(t *testing.T) {
	prevInit := inotifyInit
	inotifyInit = func() (int, error) { return -1, syscall.EMFILE }
	defer func() { inotifyInit = prevInit }()

	var reasons []string
	var mu sync.Mutex
	prevPoll, prevHook := pollFallback, watchFallback
	pollFallback = 50 * time.Millisecond
	watchFallback = func(reason string, err error) {
		mu.Lock()
		reasons = append(reasons, reason)
		mu.Unlock()
	}
	defer func() { pollFallback, watchFallback = prevPoll, prevHook }()

	ca := testpki.NewCA(t, "ca")
	d := newPKIDir(t, ca.Issue(t, testpki.LeafOptions{}), ca.PEM(), nil)
	r := newReloader(t, Files{Cert: d.files.Cert, Key: d.files.Key, Roots: d.files.Roots})
	d.write(t, ca.Issue(t, testpki.LeafOptions{}), nil, nil)
	waitGeneration(t, r, 2, 5*time.Second)
	r.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(reasons) != 1 || reasons[0] != "init" {
		t.Errorf("fallback reasons = %v, want [init]", reasons)
	}
}

func TestWatchRewrite(t *testing.T) {
	watchForTest(t)
	ca := testpki.NewCA(t, "ca")
	d := newPKIDir(t, ca.Issue(t, testpki.LeafOptions{}), ca.PEM(), nil)
	r := newReloader(t, Files{Cert: d.files.Cert, Key: d.files.Key, Roots: d.files.Roots})

	next := ca.Issue(t, testpki.LeafOptions{})
	d.write(t, next, nil, nil)
	waitGeneration(t, r, 2, 5*time.Second)
	if !r.Current().Certificate.Leaf.Equal(next.Cert) {
		t.Error("new leaf not in service")
	}
}

// kubeSecretVolume lays out files the way the kubelet does for a Secret
// volume: tls.crt -> ..data/tls.crt, ..data -> ..<timestamp>/.
type kubeSecretVolume struct {
	dir string
	n   int
}

func (k *kubeSecretVolume) update(t *testing.T, files map[string][]byte) {
	t.Helper()
	k.n++
	ts := filepath.Join(k.dir, "..2026_10_13_00_00_0"+string(rune('0'+k.n)))
	if err := os.Mkdir(ts, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(ts, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old, _ := os.Readlink(filepath.Join(k.dir, "..data"))
	tmp := filepath.Join(k.dir, "..data_tmp")
	if err := os.Symlink(filepath.Base(ts), tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(k.dir, "..data")); err != nil {
		t.Fatal(err)
	}
	for name := range files {
		link := filepath.Join(k.dir, name)
		if _, err := os.Lstat(link); err != nil {
			if err := os.Symlink(filepath.Join("..data", name), link); err != nil {
				t.Fatal(err)
			}
		}
	}
	if old != "" {
		if err := os.RemoveAll(filepath.Join(k.dir, old)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWatchKubernetesSecretVolume(t *testing.T) {
	watchForTest(t)
	ca := testpki.NewCA(t, "ca")
	vol := &kubeSecretVolume{dir: t.TempDir()}
	leaf := ca.Issue(t, testpki.LeafOptions{})
	vol.update(t, map[string][]byte{"tls.crt": leaf.CertPEM, "tls.key": leaf.KeyPEM, "ca.crt": ca.PEM()})

	r := newReloader(t, Files{
		Cert:  filepath.Join(vol.dir, "tls.crt"),
		Key:   filepath.Join(vol.dir, "tls.key"),
		Roots: filepath.Join(vol.dir, "ca.crt"),
	})

	for i := 2; i <= 4; i++ {
		leaf = ca.Issue(t, testpki.LeafOptions{})
		vol.update(t, map[string][]byte{"tls.crt": leaf.CertPEM, "tls.key": leaf.KeyPEM, "ca.crt": ca.PEM()})
		waitGeneration(t, r, uint64(i), 5*time.Second)
		if !r.Current().Certificate.Leaf.Equal(leaf.Cert) {
			t.Fatalf("update %d: new leaf not in service", i)
		}
	}
	if st := r.Stats(); st.Invalid != 0 || st.ReadError != 0 {
		t.Errorf("Stats() = %+v, want no failures", st)
	}
}
