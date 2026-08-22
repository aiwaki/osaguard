//go:build darwin && cgo

package darwinbridge

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReadAuthSnapshotDoesNotMisclassifyCurrentUI(t *testing.T) {
	snapshot, err := ReadAuthSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("auth snapshot: %+v", snapshot)
	if snapshot.IsAuthDialog && (!snapshot.AccessibilityTrusted || !snapshot.AppleSigned || !snapshot.AppFrontmost ||
		!snapshot.AppOnscreen || !snapshot.FocusedEnabled || snapshot.SecureFieldCount != 1 ||
		snapshot.CodeIdentifier != "com.apple.SecurityAgent" ||
		snapshot.ExecutablePath != "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent" ||
		snapshot.StartSeconds <= 0 || snapshot.StartMicroseconds < 0) {
		t.Fatalf("invalid positive classification: %+v", snapshot)
	}
	if snapshot.AccessibilityTrusted != AccessibilityTrusted() {
		t.Fatal("read-only Accessibility status disagrees with authorization snapshot")
	}
}

func TestPromptPasswordRejectsUnsupportedLocaleBeforeShowingUI(t *testing.T) {
	if _, err := PromptPassword("fr"); err == nil {
		t.Fatal("unsupported locale must fail before opening AppKit UI")
	}
}

func TestLegacyKeychainIntegrationOptInIsRejected(t *testing.T) {
	// The former opt-in tests called SecItem APIs without kSecUseKeychain. On
	// macOS that means the current user's default login Keychain, so simply
	// setting an environment variable could create, replace, or delete real
	// Keychain items. The ACL-poisoning test additionally tried to change the
	// owner of the real protected-state item, which prompts SecurityAgent.
	//
	// Do not bring an in-process substitute back here: production deliberately
	// does not expose a test-only keychain selector. Switching the user-wide
	// Keychain search list/default from a test is unsafe for concurrently
	// running applications and can leave the account misconfigured on a crash.
	// Live verification belongs in a disposable macOS account or VM, not go
	// test on a developer profile. See KEYCHAIN_TESTING.md.
	if os.Getenv("OSAGUARD_KEYCHAIN_INTEGRATION") == "1" {
		t.Fatal("OSAGUARD_KEYCHAIN_INTEGRATION is intentionally unsupported: refusing to access this user's login Keychain; see KEYCHAIN_TESTING.md")
	}
}

func TestDeleteAllUsesVerifiedKeychainItemReferences(t *testing.T) {
	// This is a source-boundary regression test, not a live Keychain test. The
	// production function must enumerate the dedicated service, prove every
	// candidate has OsaGuard's caller-only ACL, and delete only those references.
	// A direct SecItemDelete(service_query) would let a colliding same-service
	// item bypass that proof; running that scenario in a developer Keychain is
	// prohibited by KEYCHAIN_TESTING.md.
	source, err := os.ReadFile("bridge_darwin.c")
	if err != nil {
		t.Fatal(err)
	}
	const startMarker = "int og_keychain_delete_all(char *err, size_t err_len) {"
	start := strings.Index(string(source), startMarker)
	if start < 0 {
		t.Fatal("delete-all Keychain implementation is missing")
	}
	function := string(source[start:])
	if end := strings.Index(function, "\nint og_integrity_state_store("); end >= 0 {
		function = function[:end]
	}
	for _, required := range []string{
		"kSecMatchLimitAll",
		"og_item_has_caller_only_access",
		"kSecMatchItemList",
		"SecItemDelete(delete_query)",
	} {
		if !strings.Contains(function, required) {
			t.Fatalf("delete-all implementation is missing %q", required)
		}
	}
	if strings.Contains(function, "SecItemDelete(query)") {
		t.Fatal("delete-all must not delete a broad service query directly")
	}
}

func TestTargetedInjectionIntoLiveAuthorizationField(t *testing.T) {
	pidText := os.Getenv("OSAGUARD_AUTH_INTEGRATION_PID")
	if pidText == "" {
		t.Skip("set OSAGUARD_AUTH_INTEGRATION_PID for the guarded live test")
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil {
		t.Fatal(err)
	}
	before, err := ReadAuthSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !before.IsAuthDialog || before.PID != pid || before.FocusedValueLength != 0 {
		t.Fatalf("live auth precondition failed: %+v", before)
	}
	if err := InjectTextToPID(pid, "X"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	after, err := ReadAuthSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if after.PID != pid || after.FocusedValueLength != 1 {
		t.Fatalf("targeted test character was not observed in the same secure field: %+v", after)
	}
}

func TestListOsaScripts(t *testing.T) {
	processes, err := ListOsaScripts(uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	for _, process := range processes {
		if process.ExecutablePath != "/usr/bin/osascript" || len(process.Arguments) == 0 ||
			!process.ParentCodeValid || process.ParentCodeIdentifier == "" || process.ParentCDHash == "" {
			t.Fatalf("invalid osascript process: %+v", process)
		}
	}
}

func TestParseKernProcArgsRejectsTruncatedData(t *testing.T) {
	if _, err := parseKernProcArgs([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected truncated data to fail")
	}
}
