//go:build darwin

package processhardening

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

var hardenOnce sync.Once
var hardenErr error

// Harden disables core dumps and debugger attachment for the entire process.
// It is idempotent because the Go archive and the watcher share the Tauri
// process and may both request the same startup hardening.
func Harden() error {
	hardenOnce.Do(func() {
		if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
			hardenErr = fmt.Errorf("disable core dumps: %w", err)
			return
		}
		if err := unix.PtraceDenyAttach(); err != nil {
			hardenErr = fmt.Errorf("deny debugger attachment: %w", err)
		}
	})
	return hardenErr
}
