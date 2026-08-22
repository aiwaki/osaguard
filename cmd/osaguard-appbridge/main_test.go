//go:build darwin && cgo

package main

import (
	"os"
	"testing"
	"time"

	"github.com/aiwaki/osaguard/internal/autotype"
)

func TestUniversalWatcherStopsOnControlEOF(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		done <- runUniversalWatcherWithOptions("integration-test", int(reader.Fd()), autotype.WatchOptions{DryRun: true})
	}()
	time.Sleep(150 * time.Millisecond)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-process watcher did not terminate after control EOF")
	}
}

func TestUniversalWatcherRejectsInvalidControlFD(t *testing.T) {
	if err := runUniversalWatcherWithOptions("integration-test", -1, autotype.WatchOptions{DryRun: true}); err == nil {
		t.Fatal("invalid watcher control descriptor unexpectedly accepted")
	}
}
