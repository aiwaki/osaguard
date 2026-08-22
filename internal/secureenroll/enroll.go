package secureenroll

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/aiwaki/osaguard/internal/darwinbridge"
	"github.com/aiwaki/osaguard/internal/processhardening"
	"golang.org/x/sys/unix"
)

type Outcome string

const (
	Saved     Outcome = "saved"
	Cancelled Outcome = "cancelled"
)

type Actions struct {
	// Harden must complete before Prompt can expose password bytes to this
	// process. Keeping it in the enrollment contract makes a future caller
	// fail closed instead of silently reintroducing an unhardened prompt.
	Harden func() error
	Prompt func(string) ([]byte, error)
	Store  func(string, []byte) error
	Lock   func([]byte) error
	Unlock func([]byte) error
}

var NativeActions = Actions{
	Harden: processhardening.Harden,
	Prompt: darwinbridge.PromptPassword,
	Store:  darwinbridge.KeychainStore,
	Lock:   unix.Mlock,
	Unlock: unix.Munlock,
}

func Run(account, locale string, actions Actions) (Outcome, error) {
	if !ValidAccount(account) || (locale != "system" && locale != "ru" && locale != "en") {
		return "", errors.New("invalid account or locale")
	}
	if actions.Harden == nil || actions.Prompt == nil || actions.Store == nil || actions.Lock == nil || actions.Unlock == nil {
		return "", errors.New("password enrollment actions are incomplete")
	}
	if err := actions.Harden(); err != nil {
		return "", fmt.Errorf("harden password process: %w", err)
	}
	secret, err := actions.Prompt(locale)
	if err != nil {
		Wipe(secret)
		if errors.Is(err, darwinbridge.ErrPasswordPromptCanceled) {
			return Cancelled, nil
		}
		return "", err
	}
	if len(secret) == 0 || len(secret) > 1024 || !utf8.Valid(secret) || ContainsForbiddenSecretByte(secret) {
		Wipe(secret)
		return "", errors.New("password must be valid UTF-8, contain no line breaks, and be 1 to 1024 bytes")
	}
	if err := actions.Lock(secret); err != nil {
		Wipe(secret)
		return "", fmt.Errorf("lock password memory: %w", err)
	}
	defer func() {
		Wipe(secret)
		_ = actions.Unlock(secret)
	}()
	if err := actions.Store(account, secret); err != nil {
		return "", err
	}
	return Saved, nil
}

func RunNative(account, locale string) (Outcome, error) {
	return Run(account, locale, NativeActions)
}

func ValidAccount(account string) bool {
	return account != "" && len(account) <= 128 && !strings.ContainsAny(account, "\x00\r\n")
}

func ContainsForbiddenSecretByte(value []byte) bool {
	return bytes.IndexByte(value, 0) >= 0 || bytes.IndexByte(value, '\r') >= 0 || bytes.IndexByte(value, '\n') >= 0
}

func Wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
	runtime.KeepAlive(value)
}
