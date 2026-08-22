//go:build darwin && cgo

package darwinbridge

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClassifyBridgeErrorPreservesKeychainErrorTypes(t *testing.T) {
	tests := []struct {
		message string
		target  error
	}{
		{
			message: "keychain_interaction_not_allowed: load password from Keychain",
			target:  ErrKeychainInteractionNotAllowed,
		},
		{
			message: "keychain_access_conflict: complete access template does not match the current application",
			target:  ErrKeychainItemNeedsReenrollment,
		},
	}
	for _, test := range tests {
		err := classifyBridgeError(test.message)
		if !errors.Is(err, test.target) {
			t.Fatalf("classifyBridgeError(%q) = %v; want errors.Is(_, %v)", test.message, err, test.target)
		}
		if !strings.HasPrefix(err.Error(), strings.SplitN(test.message, ":", 2)[0]+":") {
			t.Fatalf("classifyBridgeError(%q) lost its machine-readable code: %v", test.message, err)
		}
	}
}

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

func TestDecodeKeychainItemStatePreservesReenrollmentBoundary(t *testing.T) {
	tests := []struct {
		result int32
		state  KeychainItemState
		valid  bool
	}{
		{result: 0, state: KeychainItemMissing, valid: true},
		{result: 1, state: KeychainItemReady, valid: true},
		{result: 2, state: KeychainItemNeedsReenrollment, valid: true},
		{result: -1, valid: false},
		{result: 3, valid: false},
	}
	for _, test := range tests {
		state, valid := decodeKeychainItemState(test.result)
		if state != test.state || valid != test.valid {
			t.Fatalf("decodeKeychainItemState(%d) = (%q, %t), want (%q, %t)", test.result, state, valid, test.state, test.valid)
		}
	}
}

func TestKeychainInspectionDoesNotCollapseACLMismatchIntoFailure(t *testing.T) {
	source, err := os.ReadFile("bridge_darwin.c")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"return caller_only == 0 ? 2 : -1;",
		"return item_state;",
	} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("Keychain state inspection is missing typed ACL-mismatch mapping %q", required)
		}
	}
}

func TestV2KeychainServicesNeverQueryLegacyPreviewItems(t *testing.T) {
	source, err := os.ReadFile("bridge_darwin.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		`OG_KEYCHAIN_SERVICE = "dev.aiwaki.osaguard.admin-password.v2"`,
		`OG_INTEGRITY_SERVICE = "dev.aiwaki.osaguard.integrity-state.v2"`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("v2 Keychain boundary is missing %q", required)
		}
	}
	for _, legacy := range []string{
		`OG_KEYCHAIN_SERVICE = "dev.aiwaki.osaguard.admin-password";`,
		`OG_INTEGRITY_SERVICE = "dev.aiwaki.osaguard.integrity-state";`,
	} {
		if strings.Contains(text, legacy) {
			t.Fatalf("production still targets legacy preview Keychain service %q", legacy)
		}
	}
	if strings.Contains(text, "SecKeychainItemSetAccess(") {
		t.Fatal("the v2 bridge must never transfer ownership of a stale Keychain item")
	}
	for _, errorCode := range []string{
		"keychain_interaction_not_allowed:",
		"keychain_access_conflict:",
	} {
		if !strings.Contains(text, errorCode) {
			t.Fatalf("typed Keychain error code is missing %q", errorCode)
		}
	}
}

func TestExistingV2KeychainUpdateIsCallerOnlyAndValueOnly(t *testing.T) {
	source, err := os.ReadFile("bridge_darwin.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	const updateMarker = "static int og_keychain_update_existing_item("
	start := strings.Index(text, updateMarker)
	if start < 0 {
		t.Fatal("existing-item Keychain update helper is missing")
	}
	update := text[start:]
	if end := strings.Index(update, "\nstatic int og_keychain_store_for_service("); end >= 0 {
		update = update[:end]
	}

	for _, required := range []string{
		"og_item_has_caller_only_access(item, label, err, err_len) != 1",
		"CFDictionarySetValue(update_query, kSecMatchItemList, item_list);",
		"CFDictionarySetValue(updates, kSecValueData, data);",
		"og_sec_item_update(update_query, updates)",
	} {
		if !strings.Contains(update, required) {
			t.Fatalf("existing-item update path is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"kSecAttrAccess",
		"SecAccessCreate(",
		"SecKeychainItemSetAccess(",
		"SecItemDelete(",
	} {
		if strings.Contains(update, forbidden) {
			t.Fatalf("existing v2 value update must not contain %q", forbidden)
		}
	}
}

func TestAllProductionSecItemOperationsSuppressAuthenticationUI(t *testing.T) {
	source, err := os.ReadFile("bridge_darwin.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"SecKeychainSetUserInteractionAllowed(false)",
		"status == errSecInteractionNotAllowed || status == errSecInteractionRequired",
		"CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);",
		"og_keychain_suppress_authentication_ui(query);",
		"og_keychain_suppress_authentication_ui(attributes);",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("authentication-UI suppression is missing %q", required)
		}
	}

	const wrappersMarker = "static OSStatus og_sec_item_copy_matching("
	const serviceQueryMarker = "static CFMutableDictionaryRef og_keychain_service_query("
	start := strings.Index(text, wrappersMarker)
	end := strings.Index(text, serviceQueryMarker)
	if start < 0 || end <= start {
		t.Fatal("central SecItem wrappers are missing")
	}
	wrappers := text[start:end]
	if got := strings.Count(wrappers, "og_keychain_suppress_authentication_ui("); got != 4 {
		t.Fatalf("SecItem wrappers call authentication suppression %d times; want 4", got)
	}
	if got := strings.Count(wrappers, "og_keychain_require_noninteractive()"); got != 4 {
		t.Fatalf("SecItem wrappers install the legacy interaction guard %d times; want 4", got)
	}
	for _, rawCall := range []string{
		"SecItemCopyMatching(",
		"SecItemUpdate(",
		"SecItemAdd(",
		"SecItemDelete(",
	} {
		if got := strings.Count(text, rawCall); got != 1 {
			t.Fatalf("raw %s occurs %d times; every production call must use its suppressing wrapper", rawCall, got)
		}
	}
}

func TestCompleteCallerOnlyAccessTemplateIsFailClosedAndNoninteractive(t *testing.T) {
	source, err := os.ReadFile("bridge_darwin.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	const copyMarker = "static OSStatus og_keychain_item_copy_access_noninteractive("
	const itemMarker = "static int og_item_has_caller_only_access("
	copyStart := strings.Index(text, copyMarker)
	copyEnd := strings.Index(text, itemMarker)
	if copyStart < 0 || copyEnd <= copyStart {
		t.Fatal("guarded legacy Keychain access wrapper is missing")
	}
	copyAccess := text[copyStart:copyEnd]
	guardIndex := strings.Index(copyAccess, "og_keychain_require_noninteractive()")
	rawIndex := strings.Index(copyAccess, "SecKeychainItemCopyAccess(item, access)")
	if guardIndex < 0 || rawIndex < 0 || guardIndex > rawIndex {
		t.Fatal("legacy interaction guard must succeed before SecKeychainItemCopyAccess")
	}
	if got := strings.Count(text, "SecKeychainItemCopyAccess("); got != 1 {
		t.Fatalf("raw SecKeychainItemCopyAccess occurs %d times; want only the guarded wrapper", got)
	}

	const matchMarker = "static int og_access_matches_template("
	const accessMarker = "static int og_access_is_caller_only("
	matchStart := strings.Index(text, matchMarker)
	accessStart := strings.Index(text, accessMarker)
	if matchStart < 0 || accessStart <= matchStart || copyStart <= accessStart {
		t.Fatal("complete caller-only access-template helpers are missing")
	}
	matchInspection := text[matchStart:accessStart]
	guardIndex = strings.Index(matchInspection, "og_keychain_require_noninteractive()")
	ownerACLIndex := strings.Index(matchInspection, "SecAccessCopyOwnerAndACL(actual")
	if guardIndex < 0 || ownerACLIndex < 0 || guardIndex > ownerACLIndex {
		t.Fatal("process-wide interaction guard must succeed before complete SecAccess inspection")
	}
	accessCreation := text[accessStart:copyStart]
	guardIndex = strings.Index(accessCreation, "og_keychain_require_noninteractive()")
	templateIndex := strings.Index(accessCreation, "SecAccessCreate(label_string, NULL, &expected)")
	if guardIndex < 0 || templateIndex < 0 || guardIndex > templateIndex {
		t.Fatal("process-wide interaction guard must succeed before caller-only template creation")
	}

	completeInspection := text[strings.Index(text, "static int og_cfarray_equal_unordered_unique("):copyStart]
	for _, required := range []string{
		"SecAccessCopyOwnerAndACL(actual",
		"SecAccessCopyOwnerAndACL(expected",
		"SecACLCopyAuthorizations(actual)",
		"SecACLCopyAuthorizations(expected)",
		"SecACLCopyContents(actual",
		"SecACLCopyContents(expected",
		"actual_prompt != 0 || expected_prompt != 0",
		"actual_count == expected_count",
		"calloc((size_t)expected_count, sizeof(*used))",
		"og_cfarray_equal_unordered_unique",
		"keychain_access_conflict: complete access template does not match the current application",
	} {
		if !strings.Contains(completeInspection, required) {
			t.Fatalf("complete caller-only access inspection is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"SecAccessCopyMatchingACLList",
		"kSecACLAuthorizationDecrypt",
	} {
		if strings.Contains(completeInspection, forbidden) {
			t.Fatalf("production caller-only proof must not rely on partial authorization inspection %q", forbidden)
		}
	}
}

func TestTargetedDeletesUseVerifiedExactKeychainReferences(t *testing.T) {
	// Source-only regression coverage: no test may touch the developer's login
	// Keychain. Both public targeted deletes must funnel through one helper that
	// obtains a stable item reference, verifies its complete access template,
	// and deletes only that reference.
	source, err := os.ReadFile("bridge_darwin.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	const verifiedItemMarker = "static int og_keychain_copy_verified_item("
	const helperMarker = "static int og_keychain_delete_verified_item("
	const updateMarker = "static int og_keychain_update_existing_item("
	verifiedItemStart := strings.Index(text, verifiedItemMarker)
	helperStart := strings.Index(text, helperMarker)
	helperEnd := strings.Index(text, updateMarker)
	if verifiedItemStart < 0 || helperStart <= verifiedItemStart || helperEnd <= helperStart {
		t.Fatal("verified exact-reference deletion helper is missing")
	}
	verifiedItem := text[verifiedItemStart:helperStart]
	for _, required := range []string{
		"CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);",
		"CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);",
		"if (status == errSecItemNotFound) return 0;",
		"og_item_has_caller_only_access(",
		"return caller_only == 0 ? 2 : -1;",
	} {
		if !strings.Contains(verifiedItem, required) {
			t.Fatalf("verified item-reference lookup is missing %q", required)
		}
	}
	helper := text[helperStart:helperEnd]
	for _, required := range []string{
		"og_keychain_copy_verified_item(",
		"CFDictionarySetValue(delete_query, kSecMatchItemList, item_list);",
		"og_sec_item_delete(delete_query)",
	} {
		if !strings.Contains(helper, required) {
			t.Fatalf("verified exact-reference deletion helper is missing %q", required)
		}
	}
	verifyIndex := strings.Index(helper, "og_keychain_copy_verified_item(")
	exactIndex := strings.Index(helper, "kSecMatchItemList")
	deleteIndex := strings.Index(helper, "og_sec_item_delete(delete_query)")
	if verifyIndex < 0 || exactIndex < verifyIndex || deleteIndex < exactIndex {
		t.Fatal("targeted deletion must verify the ACL before constructing and executing its exact-reference delete")
	}

	targets := []struct {
		start string
		end   string
		label string
	}{
		{
			start: "int og_keychain_delete(const char *account, char *err, size_t err_len) {",
			end:   "\nint og_keychain_delete_all(",
			label: "OG_KEYCHAIN_LABEL",
		},
		{
			start: "int og_integrity_state_delete(char *err, size_t err_len) {",
			end:   "\n// Test-only ACL introspection",
			label: "OG_INTEGRITY_LABEL",
		},
	}
	for _, target := range targets {
		start := strings.Index(text, target.start)
		if start < 0 {
			t.Fatalf("targeted delete %q is missing", target.start)
		}
		function := text[start:]
		if end := strings.Index(function, target.end); end >= 0 {
			function = function[:end]
		} else {
			t.Fatalf("cannot isolate targeted delete %q", target.start)
		}
		for _, required := range []string{
			"og_keychain_delete_verified_item(",
			target.label,
		} {
			if !strings.Contains(function, required) {
				t.Fatalf("targeted delete %q is missing %q", target.start, required)
			}
		}
		if strings.Contains(function, "og_sec_item_delete(query)") {
			t.Fatalf("targeted delete %q must not delete its service/account query directly", target.start)
		}
	}
}

func TestVerifiedLoadsUseTheSameExactKeychainItemReference(t *testing.T) {
	// This source-only regression test models the service/account replacement
	// race. Once an item's complete access template has been verified, both
	// password and integrity reads must use that retained reference. A second
	// broad query could otherwise read a colliding record inserted between the
	// check and use.
	source, err := os.ReadFile("bridge_darwin.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	const dataHelperMarker = "static int og_keychain_copy_verified_item_data("
	const deleteHelperMarker = "static int og_keychain_delete_verified_item("
	dataHelperStart := strings.Index(text, dataHelperMarker)
	dataHelperEnd := strings.Index(text, deleteHelperMarker)
	if dataHelperStart < 0 || dataHelperEnd <= dataHelperStart {
		t.Fatal("exact verified-item data helper is missing")
	}
	dataHelper := text[dataHelperStart:dataHelperEnd]
	for _, required := range []string{
		"SecKeychainItemRef item",
		"CFDictionarySetValue(query, kSecMatchItemList, item_list);",
		"CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);",
		"og_sec_item_copy_matching(query, &result)",
		"if (status == errSecItemNotFound) return 0;",
	} {
		if !strings.Contains(dataHelper, required) {
			t.Fatalf("exact verified-item data helper is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"kSecAttrService",
		"kSecAttrAccount",
	} {
		if strings.Contains(dataHelper, forbidden) {
			t.Fatalf("exact verified-item data helper must not fall back to broad attribute %q", forbidden)
		}
	}

	loads := []struct {
		start string
		end   string
		label string
	}{
		{
			start: "int og_keychain_load(const char *account, unsigned char **secret, size_t *secret_len, char *err, size_t err_len) {",
			end:   "\nint og_keychain_exists(",
			label: "OG_KEYCHAIN_LABEL",
		},
		{
			start: "int og_integrity_state_load(unsigned char **state, size_t *state_len, char *err, size_t err_len) {",
			end:   "\nint og_integrity_state_delete(",
			label: "OG_INTEGRITY_LABEL",
		},
	}
	for _, load := range loads {
		start := strings.Index(text, load.start)
		if start < 0 {
			t.Fatalf("verified load %q is missing", load.start)
		}
		function := text[start:]
		if end := strings.Index(function, load.end); end >= 0 {
			function = function[:end]
		} else {
			t.Fatalf("cannot isolate verified load %q", load.start)
		}
		verifyIndex := strings.Index(function, "og_keychain_copy_verified_item(")
		dataIndex := strings.Index(function, "og_keychain_copy_verified_item_data(")
		if verifyIndex < 0 || dataIndex <= verifyIndex {
			t.Fatalf("verified load %q does not pass its verified exact ref into data access", load.start)
		}
		for _, required := range []string{
			load.label,
			"item, &data",
			"CFRelease(item);",
		} {
			if !strings.Contains(function, required) {
				t.Fatalf("verified load %q is missing %q", load.start, required)
			}
		}
		for _, forbidden := range []string{
			"kSecReturnData",
			"og_sec_item_copy_matching(query, &result)",
		} {
			if strings.Contains(function, forbidden) {
				t.Fatalf("verified load %q still performs a second broad query via %q", load.start, forbidden)
			}
		}
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
		"og_sec_item_delete(delete_query)",
	} {
		if !strings.Contains(function, required) {
			t.Fatalf("delete-all implementation is missing %q", required)
		}
	}
	if strings.Contains(function, "og_sec_item_delete(query)") {
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
