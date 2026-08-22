package secureenroll

import (
	"errors"
	"testing"
)

func TestRunHardensBeforePrompt(t *testing.T) {
	hardened := false
	secret := []byte("not-a-real-password")
	outcome, err := Run("alice", "en", Actions{
		Harden: func() error {
			hardened = true
			return nil
		},
		Prompt: func(string) ([]byte, error) {
			if !hardened {
				t.Fatal("prompt ran before hardening")
			}
			return secret, nil
		},
		Store:  func(string, []byte) error { return nil },
		Lock:   func([]byte) error { return nil },
		Unlock: func([]byte) error { return nil },
	})
	if err != nil || outcome != Saved {
		t.Fatalf("Run() = %q, %v; want saved, nil", outcome, err)
	}
	for index, value := range secret {
		if value != 0 {
			t.Fatalf("secret byte %d was not wiped", index)
		}
	}
}

func TestRunFailsClosedWhenHardeningFails(t *testing.T) {
	wantErr := errors.New("debugger protection unavailable")
	promptCalled := false
	outcome, err := Run("alice", "en", Actions{
		Harden: func() error { return wantErr },
		Prompt: func(string) ([]byte, error) {
			promptCalled = true
			return nil, nil
		},
		Store:  func(string, []byte) error { t.Fatal("store must not run"); return nil },
		Lock:   func([]byte) error { t.Fatal("lock must not run"); return nil },
		Unlock: func([]byte) error { t.Fatal("unlock must not run"); return nil },
	})
	if outcome != "" || !errors.Is(err, wantErr) {
		t.Fatalf("Run() = %q, %v; want empty outcome and wrapped %v", outcome, err, wantErr)
	}
	if promptCalled {
		t.Fatal("prompt must not run after hardening fails")
	}
}

func TestRunRequiresHardeningAction(t *testing.T) {
	promptCalled := false
	_, err := Run("alice", "en", Actions{
		Prompt: func(string) ([]byte, error) {
			promptCalled = true
			return nil, nil
		},
		Store:  func(string, []byte) error { return nil },
		Lock:   func([]byte) error { return nil },
		Unlock: func([]byte) error { return nil },
	})
	if err == nil || err.Error() != "password enrollment actions are incomplete" {
		t.Fatalf("missing hardening action error = %v", err)
	}
	if promptCalled {
		t.Fatal("prompt must not run without a hardening action")
	}
}
