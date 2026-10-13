//go:build linux

package keyload

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

func TestWatchRewrite(t *testing.T) {
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
