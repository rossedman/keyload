//go:build linux

package keyload

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const inotifyMask = syscall.IN_CREATE | syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO |
	syscall.IN_MOVED_FROM | syscall.IN_DELETE | syscall.IN_ATTRIB |
	syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

// Filesystems where inotify does not see changes made elsewhere.
var noInotifyFS = map[uint32]bool{
	0x6969:     true, // NFS
	0x65735546: true, // FUSE
	0x517B:     true, // SMB
	0xFF534D42: true, // CIFS
	0xFE534D42: true, // SMB2
	0x01021997: true, // 9P
	0x47504653: true, // GPFS
	0x013111A8: true, // IBRIX
	0x00C36400: true, // CEPH
	0x0BD00BD0: true, // Lustre
}

// inotifyInit creates the inotify instance; tests replace it.
var inotifyInit = func() (int, error) {
	return syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
}

// watchFallback, when set, is told why watchFiles fell back to polling. It is
// a test hook.
var watchFallback func(reason string, err error)

// fallBack reports, through the watchFallback test hook, why watching fell
// back to polling.
func fallBack(reason string, err error) {
	if watchFallback != nil {
		watchFallback(reason, err)
	}
}

// watchFiles watches the directories holding paths, and those holding their
// symlink targets, and calls changed after a burst of events settles.
// Watching directories rather than files is what makes the Kubernetes Secret
// volume update visible: the kubelet writes a new timestamped directory and
// atomically renames the ..data symlink in the volume's root. It falls back
// to polling when inotify is unavailable or unsuitable.
func watchFiles(ctx context.Context, paths []string, debounce, poll time.Duration, changed func()) {
	fd, err := inotifyInit()
	if err != nil {
		// Typically EMFILE: the per-user inotify instance limit is reached.
		fallBack("init", err)
		pollFiles(ctx, poll, changed)
		return
	}
	// A non-blocking fd wrapped in os.File uses the runtime poller, so Close
	// unblocks a pending Read.
	f := os.NewFile(uintptr(fd), "inotify")
	defer f.Close()

	watches := map[string]int{} // dir -> watch descriptor
	rewatch := func() bool {
		want := watchDirs(paths)
		for dir := range want {
			if _, ok := watches[dir]; ok {
				continue
			}
			var st syscall.Statfs_t
			if err := syscall.Statfs(dir, &st); err != nil || noInotifyFS[uint32(st.Type)] {
				return false
			}
			wd, err := syscall.InotifyAddWatch(fd, dir, inotifyMask)
			if err != nil { // includes ENOSPC when the watch limit is reached
				return false
			}
			watches[dir] = wd
		}
		for dir, wd := range watches {
			if !want[dir] {
				_, _ = syscall.InotifyRmWatch(fd, uint32(wd))
				delete(watches, dir)
			}
		}
		return true
	}
	if !rewatch() {
		fallBack("watch", nil)
		pollFiles(ctx, poll, changed)
		return
	}
	// The files may have changed between the Reloader's first load and the
	// watches being added; that change produced no event. Check once now.
	// Reloading unchanged files is a no-op.
	changed()

	events := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			if _, err := f.Read(buf); err != nil {
				close(events)
				return
			}
			// Any event in a watched directory may matter; a reload of
			// unchanged material is a no-op, so there is no need to parse
			// names.
			select {
			case events <- struct{}{}:
			default:
			}
		}
	}()
	go func() {
		<-ctx.Done()
		f.Close()
	}()

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				if ctx.Err() == nil {
					fallBack("read", nil)
					pollFiles(ctx, poll, changed)
				}
				return
			}
			timer.Reset(debounce)
		case <-timer.C:
			// Symlink targets move on every Kubernetes update; follow them.
			if !rewatch() {
				fallBack("rewatch", nil)
				changed()
				pollFiles(ctx, poll, changed)
				return
			}
			changed()
		}
	}
}

// watchDirs returns the directories to watch for paths: each file's own
// directory and the directory of its resolved target.
func watchDirs(paths []string) map[string]bool {
	dirs := map[string]bool{}
	for _, p := range paths {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		dirs[filepath.Dir(p)] = true
		if real, err := filepath.EvalSymlinks(p); err == nil {
			dirs[filepath.Dir(real)] = true
		}
	}
	return dirs
}
