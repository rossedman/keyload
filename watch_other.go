//go:build !linux

package keyload

import (
	"context"
	"time"
)

// watchFiles polls on platforms without inotify support in this package.
func watchFiles(ctx context.Context, _ []string, _, poll time.Duration, changed func()) {
	pollFiles(ctx, poll, changed)
}
