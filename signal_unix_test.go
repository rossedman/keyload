//go:build unix

package keyload

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

func TestSignalTrigger(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	src := &memSource{m: Material{Roots: ca.PEM()}}
	r := newReloader(t, src, OnSignal(syscall.SIGUSR1))
	src.set(Material{Roots: testpki.NewCA(t, "ca2").PEM()})
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	waitGeneration(t, r, 2, 5*time.Second)
}
