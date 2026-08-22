package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aiwaki/osaguard/internal/autotype"
	"github.com/aiwaki/osaguard/internal/darwinbridge"
)

func TestWriteEnrollmentPolicyCreatesPrivateFileAndNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "autotype-policy.json")
	first := []byte(`{"version":1}`)
	if err := writeEnrollmentPolicy(path, first); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("policy mode is %o, want 600", info.Mode().Perm())
	}
	if err := writeEnrollmentPolicy(path, []byte(`{"version":2}`)); err == nil {
		t.Fatal("existing enrollment policy must not be overwritten")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(first)+"\n" {
		t.Fatalf("existing policy changed: %q", got)
	}
}

func TestEnrollNextRejectsExistingOutputBeforeWaiting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.json")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	err := enrollNext([]string{"--output", path, "--timeout-seconds", "10"})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("expected preflight overwrite rejection, got %v", err)
	}
}

func TestInstallAutotypePolicyRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root guard is not testable as root")
	}
	err := installAutotypePolicy([]string{"--source", "/tmp/unused"})
	if err == nil || !strings.Contains(err.Error(), "must run through sudo") {
		t.Fatalf("expected root guard, got %v", err)
	}
}

func TestUniversalModeFlagsCannotBeMixedWithExactPolicy(t *testing.T) {
	if err := watch([]string{"--universal", "--account", "alice", "--policy", "/tmp/exact.json"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("watch accepted mixed universal and exact policy flags: %v", err)
	}
	if err := autotypeStatus([]string{"--universal", "--account", "alice", "--policy", "/tmp/exact.json", "--metadata-only"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("status accepted mixed universal and exact policy flags: %v", err)
	}
	if err := watch([]string{"--account", "alice", "--dry-run"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("exact watch accepted a universal-only account flag: %v", err)
	}
}

func TestGUIEnrollmentValidatesBeforeOpeningAppKit(t *testing.T) {
	err := storePasswordGUI([]string{"--account", "alice", "--acknowledge-risk", "--locale", "fr"})
	if err == nil || !strings.Contains(err.Error(), "locale") {
		t.Fatalf("expected unsupported locale rejection, got %v", err)
	}
	if validAccountLabel("") || validAccountLabel("bad\naccount") || !validAccountLabel("alice") {
		t.Fatal("account-label validation is not fail-closed")
	}
}

func TestMachineReadableSetupStatusLinesAreStable(t *testing.T) {
	if got := accessibilityStatusLine(false); got != "accessibility=false" {
		t.Fatalf("unexpected Accessibility status: %q", got)
	}
	if got := accessibilityStatusLine(true); got != "accessibility=true" {
		t.Fatalf("unexpected Accessibility status: %q", got)
	}
	if got := passwordStatusLine(false); got != "password_saved=false" {
		t.Fatalf("unexpected password status: %q", got)
	}
	if got := passwordStatusLine(true); got != "password_saved=true" {
		t.Fatalf("unexpected password status: %q", got)
	}
	if got := passwordActionLine(passwordActionSaved); got != "password_action=saved" {
		t.Fatalf("unexpected password action: %q", got)
	}
	if got := passwordActionLine(passwordActionCancelled); got != "password_action=cancelled" {
		t.Fatalf("unexpected password cancellation: %q", got)
	}
	if got := authDialogStatusLine(false); got != "auth_dialog_active=false" {
		t.Fatalf("unexpected authorization dialog status: %q", got)
	}
	if got := authDialogStatusLine(true); got != "auth_dialog_active=true" {
		t.Fatalf("unexpected authorization dialog status: %q", got)
	}
}

func TestAuthDialogStatusRejectsArgumentsBeforeInspectingUI(t *testing.T) {
	err := authDialogStatus([]string{"unexpected"})
	if err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("expected argument rejection, got %v", err)
	}
}

func TestForgetPasswordDeletesAllOsaGuardPasswords(t *testing.T) {
	original := deleteAllOsaGuardPasswords
	called := 0
	deleteAllOsaGuardPasswords = func() error {
		called++
		return nil
	}
	t.Cleanup(func() { deleteAllOsaGuardPasswords = original })

	if err := forgetPassword(nil); err != nil {
		t.Fatalf("forget-password failed: %v", err)
	}
	if called != 1 {
		t.Fatalf("delete-all calls = %d, want 1", called)
	}
	if err := forgetPassword([]string{"--account", "legacy-label"}); err == nil || !strings.Contains(err.Error(), "every saved OsaGuard password") {
		t.Fatalf("legacy targeted deletion must be rejected explicitly, got %v", err)
	}
	if called != 1 {
		t.Fatalf("legacy account flag called deletion again: %d", called)
	}
}

func TestForgetPasswordPropagatesDeleteAllFailure(t *testing.T) {
	original := deleteAllOsaGuardPasswords
	wantErr := errors.New("keychain unavailable")
	deleteAllOsaGuardPasswords = func() error { return wantErr }
	t.Cleanup(func() { deleteAllOsaGuardPasswords = original })

	if err := forgetPassword(nil); !errors.Is(err, wantErr) {
		t.Fatalf("forget-password error = %v, want %v", err, wantErr)
	}
}

func TestStorePasswordGUICancelIsSuccessfulNoOp(t *testing.T) {
	storeCalled := false
	hardened := false
	secret := []byte("must-be-wiped-even-on-cancel")
	action, err := runStorePasswordGUI(
		[]string{"--account", "alice", "--acknowledge-risk", "--locale", "en"},
		passwordGUIActions{
			harden: func() error {
				hardened = true
				return nil
			},
			prompt: func(locale string) ([]byte, error) {
				if !hardened {
					t.Fatal("password prompt opened before process hardening")
				}
				if locale != "en" {
					t.Fatalf("unexpected locale: %q", locale)
				}
				return secret, darwinbridge.ErrPasswordPromptCanceled
			},
			store: func(string, []byte) error {
				storeCalled = true
				return nil
			},
			lock: func([]byte) error {
				t.Fatal("cancelled password must not be locked")
				return nil
			},
			unlock: func([]byte) error { return nil },
		},
	)
	if err != nil || action != passwordActionCancelled {
		t.Fatalf("cancel result = %q, %v; want cancelled, nil", action, err)
	}
	if storeCalled {
		t.Fatal("cancelled password prompt changed the Keychain")
	}
	for i, value := range secret {
		if value != 0 {
			t.Fatalf("cancelled secret byte %d was not wiped", i)
		}
	}
}

func TestStorePasswordGUISavesAndWipesSecret(t *testing.T) {
	secret := []byte("not-a-real-password")
	stored := ""
	hardened := false
	action, err := runStorePasswordGUI(
		[]string{"--account", "alice", "--acknowledge-risk"},
		passwordGUIActions{
			harden: func() error {
				hardened = true
				return nil
			},
			prompt: func(string) ([]byte, error) {
				if !hardened {
					t.Fatal("password prompt opened before process hardening")
				}
				return secret, nil
			},
			store: func(account string, value []byte) error {
				if account != "alice" {
					t.Fatalf("unexpected account: %q", account)
				}
				stored = string(value)
				return nil
			},
			lock:   func([]byte) error { return nil },
			unlock: func([]byte) error { return nil },
		},
	)
	if err != nil || action != passwordActionSaved {
		t.Fatalf("save result = %q, %v; want saved, nil", action, err)
	}
	if stored != "not-a-real-password" {
		t.Fatalf("stored secret mismatch: %q", stored)
	}
	for i, value := range secret {
		if value != 0 {
			t.Fatalf("secret byte %d was not wiped", i)
		}
	}
}

func TestStorePasswordGUIPropagatesStoreFailureAndWipesSecret(t *testing.T) {
	secret := []byte("replacement")
	wantErr := errors.New("keychain unavailable")
	action, err := runStorePasswordGUI(
		[]string{"--account", "alice", "--acknowledge-risk"},
		passwordGUIActions{
			harden: func() error { return nil },
			prompt: func(string) ([]byte, error) { return secret, nil },
			store:  func(string, []byte) error { return wantErr },
			lock:   func([]byte) error { return nil },
			unlock: func([]byte) error { return nil },
		},
	)
	if action != "" || !errors.Is(err, wantErr) {
		t.Fatalf("store failure result = %q, %v; want empty action and original error", action, err)
	}
	for i, value := range secret {
		if value != 0 {
			t.Fatalf("secret byte %d was not wiped after failure", i)
		}
	}
}

func TestHardenBeforePasswordEntryFailsClosed(t *testing.T) {
	wantErr := errors.New("debugger protection unavailable")
	err := hardenBeforePasswordEntry(func() error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("hardening error = %v, want wrapped %v", err, wantErr)
	}
	if err := hardenBeforePasswordEntry(nil); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("nil hardening action must fail closed, got %v", err)
	}
}

func TestEnrollmentDraftLoadsPrivatelyAndReplacesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "autotype-policy.json")
	first := testDraftPolicy(t, "first", "a")
	if err := writeEnrollmentPolicy(path, first); err != nil {
		t.Fatal(err)
	}
	before, err := loadEnrollmentDraft(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	second := testDraftPolicy(t, "second", "e")
	if err := replaceEnrollmentDraft(path, second); err != nil {
		t.Fatal(err)
	}
	after, err := loadEnrollmentDraft(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if before.inode == after.inode || after.policy.Rules[0].Name != "second" {
		t.Fatalf("draft was not atomically replaced: before=%+v after=%+v", before, after)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadEnrollmentDraft(path, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "mode-0600") {
		t.Fatalf("expected permissive draft rejection, got %v", err)
	}
}

func testDraftPolicy(t *testing.T, name, argumentHex string) []byte {
	t.Helper()
	rule := autotype.Rule{
		Name: name, ArgumentsSHA256: strings.Repeat(argumentHex, 64),
		ParentExecutable: "/usr/bin/true", ParentSHA256: strings.Repeat("b", 64),
		ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40),
		AuthContextSHA256: strings.Repeat("c", 64),
	}
	data, err := autotype.MarshalSuggestedPolicy("alice", []autotype.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
