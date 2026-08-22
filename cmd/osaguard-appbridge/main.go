//go:build darwin && cgo

// Command osaguard-appbridge builds a macOS C archive linked directly into the
// Tauri process. Password bytes never cross this ABI: AppKit enrollment,
// memory locking/erasure, Keychain persistence, retrieval, and targeted typing
// all remain in Go/native code.
package main

/*
#include <stdint.h>
#include <stddef.h>
#include <string.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"unsafe"

	"github.com/aiwaki/osaguard/internal/autotype"
	"github.com/aiwaki/osaguard/internal/darwinbridge"
	"github.com/aiwaki/osaguard/internal/processhardening"
	"github.com/aiwaki/osaguard/internal/secureenroll"
	"golang.org/x/sys/unix"
)

const (
	abiOK                C.int32_t = 0
	abiPasswordCancelled C.int32_t = 1
	abiStateMissing      C.int32_t = 0
	abiStatePaused       C.int32_t = 1
	abiStateEnabled      C.int32_t = 2
	abiError             C.int32_t = -1
	maxCallerErrorBuffer           = 4096
)

var passwordPromptActive atomic.Bool
var watcherActive atomic.Bool

func main() {}

//export osaguard_harden_process
func osaguard_harden_process(errBuf *C.char, errLen C.size_t) C.int32_t {
	if err := processhardening.Harden(); err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	return abiOK
}

//export osaguard_password_prompt_and_store
func osaguard_password_prompt_and_store(account *C.char, locale *C.char, errBuf *C.char, errLen C.size_t) C.int32_t {
	if !passwordPromptActive.CompareAndSwap(false, true) {
		writeABIError(errBuf, errLen, errors.New("password prompt is already open"))
		return abiError
	}
	defer passwordPromptActive.Store(false)
	accountValue, err := boundedCString(account, 128, "account")
	if err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	localeValue, err := boundedCString(locale, 16, "locale")
	if err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	outcome, err := secureenroll.RunNative(accountValue, localeValue)
	if err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	if outcome == secureenroll.Cancelled {
		return abiPasswordCancelled
	}
	return abiOK
}

//export osaguard_password_exists
func osaguard_password_exists(account *C.char, errBuf *C.char, errLen C.size_t) C.int32_t {
	accountValue, err := boundedCString(account, 128, "account")
	if err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	exists, err := darwinbridge.KeychainExists(accountValue)
	if err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	if exists {
		return 1
	}
	return 0
}

//export osaguard_password_delete
func osaguard_password_delete(account *C.char, errBuf *C.char, errLen C.size_t) C.int32_t {
	accountValue, err := boundedCString(account, 128, "account")
	if err == nil {
		err = darwinbridge.KeychainDelete(accountValue)
	}
	if err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	return abiOK
}

//export osaguard_password_delete_all
func osaguard_password_delete_all(errBuf *C.char, errLen C.size_t) C.int32_t {
	if err := darwinbridge.KeychainDeleteAll(); err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	return abiOK
}

//export osaguard_auth_dialog_active
func osaguard_auth_dialog_active(errBuf *C.char, errLen C.size_t) C.int32_t {
	snapshot, err := darwinbridge.ReadAuthSnapshot()
	if err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	if snapshot.IsAuthDialog {
		return 1
	}
	return 0
}

//export osaguard_watcher_run
func osaguard_watcher_run(account *C.char, controlFD C.int32_t, errBuf *C.char, errLen C.size_t) C.int32_t {
	accountValue, err := boundedCString(account, 128, "account")
	if err == nil {
		err = runUniversalWatcher(accountValue, int(controlFD))
	}
	if err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	return abiOK
}

//export osaguard_integrity_state_get
func osaguard_integrity_state_get(errBuf *C.char, errLen C.size_t) C.int32_t {
	state, exists, err := darwinbridge.IntegrityStateLoad()
	if err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	if !exists {
		return abiStateMissing
	}
	switch state {
	case darwinbridge.IntegrityStatePaused:
		return abiStatePaused
	case darwinbridge.IntegrityStateEnabled:
		return abiStateEnabled
	default:
		writeABIError(errBuf, errLen, errors.New("unknown protected product state"))
		return abiError
	}
}

//export osaguard_integrity_state_set
func osaguard_integrity_state_set(state C.int32_t, errBuf *C.char, errLen C.size_t) C.int32_t {
	var value darwinbridge.IntegrityState
	switch state {
	case abiStatePaused:
		value = darwinbridge.IntegrityStatePaused
	case abiStateEnabled:
		value = darwinbridge.IntegrityStateEnabled
	default:
		writeABIError(errBuf, errLen, errors.New("invalid protected product state"))
		return abiError
	}
	if err := darwinbridge.IntegrityStateStore(value); err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	return abiOK
}

//export osaguard_integrity_state_delete
func osaguard_integrity_state_delete(errBuf *C.char, errLen C.size_t) C.int32_t {
	if err := darwinbridge.IntegrityStateDelete(); err != nil {
		writeABIError(errBuf, errLen, err)
		return abiError
	}
	return abiOK
}

func runUniversalWatcher(account string, controlFD int) error {
	return runUniversalWatcherWithOptions(account, controlFD, autotype.WatchOptions{})
}

func runUniversalWatcherWithOptions(account string, controlFD int, options autotype.WatchOptions) error {
	if !secureenroll.ValidAccount(account) {
		return errors.New("invalid account")
	}
	if controlFD < 0 {
		return errors.New("invalid watcher control file descriptor")
	}
	if !watcherActive.CompareAndSwap(false, true) {
		return errors.New("watcher is already running")
	}
	defer watcherActive.Store(false)

	ownedFD, err := unix.Dup(controlFD)
	if err != nil {
		return fmt.Errorf("duplicate watcher control file descriptor: %w", err)
	}
	defer unix.Close(ownedFD)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcherDone := make(chan struct{})
	readerDone := make(chan error, 1)
	go func() {
		pollFDs := []unix.PollFd{{Fd: int32(ownedFD), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		for {
			select {
			case <-watcherDone:
				readerDone <- nil
				return
			default:
			}
			count, pollErr := unix.Poll(pollFDs, 100)
			if pollErr == unix.EINTR {
				continue
			}
			if pollErr != nil {
				cancel()
				readerDone <- fmt.Errorf("poll watcher control descriptor: %w", pollErr)
				return
			}
			if count == 0 {
				continue
			}
			var oneByte [1]byte
			_, readErr := unix.Read(ownedFD, oneByte[:])
			if readErr == unix.EINTR {
				continue
			}
			cancel() // one byte or EOF both terminate the watcher
			readerDone <- readErr
			return
		}
	}()

	policy := autotype.NewUniversalPolicy(account)
	options.Logger = log.New(os.Stderr, "osaguard: ", log.LstdFlags)
	watcher, err := autotype.NewWatcher(policy, options)
	if err == nil {
		err = watcher.Run(ctx)
	}
	close(watcherDone)
	controlErr := <-readerDone
	if errors.Is(err, context.Canceled) && controlErr != nil {
		return controlErr
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func boundedCString(value *C.char, maximum int, name string) (string, error) {
	if value == nil {
		return "", fmt.Errorf("%s is missing", name)
	}
	length := int(C.strnlen(value, C.size_t(maximum+1)))
	if length == 0 || length > maximum {
		return "", fmt.Errorf("%s must contain 1 to %d bytes", name, maximum)
	}
	return C.GoStringN(value, C.int(length)), nil
}

func writeABIError(buffer *C.char, length C.size_t, err error) {
	if buffer == nil || length == 0 || err == nil {
		return
	}
	n := int(length)
	if n > maxCallerErrorBuffer {
		n = maxCallerErrorBuffer
	}
	bytes := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), n)
	clear(bytes)
	copy(bytes[:n-1], err.Error())
}
