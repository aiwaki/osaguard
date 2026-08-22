//go:build !darwin

package processhardening

import "errors"

func Harden() error { return errors.New("process hardening requires macOS") }
