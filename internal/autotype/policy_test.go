package autotype

import (
	"os"
	"strings"
	"testing"

	"github.com/aiwaki/osaguard/internal/darwinbridge"
)

func TestInlineArgumentsFingerprintChangesWithSource(t *testing.T) {
	a := hashArguments([]string{"/usr/bin/osascript", "-e", `do shell script "id" with administrator privileges`})
	b := hashArguments([]string{"/usr/bin/osascript", "-e", `do shell script "rm" with administrator privileges`})
	if a == b {
		t.Fatal("different scripts must have different fingerprints")
	}
}

func TestFingerprintRejectsUserOwnedScriptFile(t *testing.T) {
	script := t.TempDir() + "/test.scpt"
	if err := os.WriteFile(script, []byte("return 1"), 0644); err != nil {
		t.Fatal(err)
	}
	process := darwinbridge.ProcessInfo{
		PID: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/usr/bin/true", ParentCodeValid: true,
		ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40),
		Arguments: []string{"/usr/bin/osascript", script},
	}
	if _, err := FingerprintProcess(process); err == nil || !strings.Contains(err.Error(), "not root-trusted") {
		t.Fatalf("expected user-owned script rejection, got %v", err)
	}
}

func TestScriptFileFromArgumentsRejectsStdinAndRelativeFiles(t *testing.T) {
	for _, args := range [][]string{
		{"/usr/bin/osascript"},
		{"/usr/bin/osascript", "-"},
		{"/usr/bin/osascript", "relative.scpt"},
	} {
		if _, err := scriptFileFromArguments(args); err == nil {
			t.Fatalf("expected args to fail: %v", args)
		}
	}
}

func TestPolicyRejectsIncompleteRule(t *testing.T) {
	_, err := Decode(strings.NewReader(`{"version":1,"account":"alice","rules":[{"name":"x"}]}`))
	if err == nil {
		t.Fatal("expected incomplete rule to fail")
	}
}

func TestUniversalPolicyIsExplicitAndInMemoryOnly(t *testing.T) {
	p := NewUniversalPolicy("alice")
	if !p.IsUniversal() || len(p.Rules) != 0 {
		t.Fatalf("unexpected universal policy: %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalPolicy(p); err == nil || !strings.Contains(err.Error(), "in-memory only") {
		t.Fatalf("universal policy must not be serialized, got %v", err)
	}
	if err := (&Policy{Version: 1, Account: "alice"}).Validate(); err == nil {
		t.Fatal("exact mode must still require at least one enrolled rule")
	}
	p.Rules = []Rule{{Name: "unexpected"}}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "must not contain") {
		t.Fatalf("universal mode must reject enrolled rules, got %v", err)
	}
}

func TestUniversalMatchCapturesAnyGenuineOsaScriptWithoutAppBinding(t *testing.T) {
	p := NewUniversalPolicy("alice")
	process := darwinbridge.ProcessInfo{
		PID: 7, UID: uint32(os.Getuid()), StartSeconds: 123, ExecutablePath: "/usr/bin/osascript",
		ParentPath: "/Users/alice/bin/unsigned-tool", ParentCodeValid: false,
		Arguments: []string{"/usr/bin/osascript", "-e", `do shell script "id" with administrator privileges`},
	}
	rule, err := p.Match(process)
	if err != nil {
		t.Fatal(err)
	}
	if rule == nil || !rule.universalRequest || rule.AuthContextSHA256 != "" ||
		rule.ArgumentsSHA256 != hashArguments(process.Arguments) || rule.ParentExecutable != process.ParentPath {
		t.Fatalf("unexpected operation-local rule: %+v", rule)
	}
	process.ExecutablePath = "/tmp/osascript"
	if _, err := p.Match(process); err == nil {
		t.Fatal("universal mode must still require the genuine /usr/bin/osascript executable")
	}
	process.ExecutablePath = "/usr/bin/osascript"
	process.UID++
	if _, err := p.Match(process); err == nil {
		t.Fatal("universal mode must reject an osascript process owned by another user")
	}
}

func TestPolicyRejectsDuplicateKeys(t *testing.T) {
	_, err := Decode(strings.NewReader(`{"version":1,"version":1,"account":"alice","rules":[]}`))
	if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("expected duplicate-key rejection, got %v", err)
	}
}

func TestDecodeRejectsOversizeAndDeeplyNestedInput(t *testing.T) {
	if _, err := Decode(strings.NewReader(strings.Repeat(" ", MaxPolicyBytes+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected bounded-read rejection, got %v", err)
	}
	nested := strings.Repeat("[", 66) + strings.Repeat("]", 66)
	if _, err := Decode(strings.NewReader(nested)); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("expected nesting-depth rejection, got %v", err)
	}
}

func TestMatchRequiresEveryFingerprintField(t *testing.T) {
	p := &Policy{Version: 1, Account: "alice", Rules: []Rule{{
		Name: "test", ArgumentsSHA256: strings.Repeat("a", 64),
		ParentExecutable: "/usr/bin/true", ParentSHA256: strings.Repeat("b", 64),
		ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40), AuthContextSHA256: strings.Repeat("c", 64),
	}}}
	process := darwinbridge.ProcessInfo{PID: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/usr/bin/true", ParentCodeValid: true, ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40), Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	match, err := p.Match(process)
	if err != nil {
		t.Fatal(err)
	}
	if match != nil {
		t.Fatal("unexpected partial match")
	}
}

func TestMatchRejectsChangedRuntimeParentIdentity(t *testing.T) {
	parent, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	process := darwinbridge.ProcessInfo{PID: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: parent, ParentCodeValid: true, ParentCodeIdentifier: "com.example.parent", ParentCDHash: strings.Repeat("d", 40), Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	fingerprint, err := FingerprintProcess(process)
	if err != nil {
		t.Fatal(err)
	}
	rule := SuggestedRule("test", fingerprint, strings.Repeat("c", 64))
	p := &Policy{Version: 1, Account: "alice", Rules: []Rule{rule}}
	if match, err := p.Match(process); err != nil || match == nil {
		t.Fatalf("baseline identity should match; match=%v err=%v", match, err)
	}
	process.ParentCodeIdentifier = "com.example.other"
	if match, err := p.Match(process); err != nil || match != nil {
		t.Fatalf("different identifier must not match; match=%v err=%v", match, err)
	}
	process.ParentCodeIdentifier = rule.ParentCodeIdentifier
	process.ParentCDHash = strings.Repeat("e", 40)
	if match, err := p.Match(process); err != nil || match != nil {
		t.Fatalf("different CDHash must not match; match=%v err=%v", match, err)
	}
}

func TestAppendRulePreservesSettingsAndRejectsDuplicateFingerprint(t *testing.T) {
	base := Rule{
		Name: "first", ArgumentsSHA256: strings.Repeat("a", 64),
		ParentExecutable: "/usr/bin/true", ParentSHA256: strings.Repeat("b", 64),
		ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40),
		AuthContextSHA256: strings.Repeat("c", 64),
	}
	p := &Policy{Version: 1, Account: "alice", PollMilliseconds: 250, CooldownSeconds: 90, Rules: []Rule{base}}
	second := base
	second.Name = "second"
	second.ArgumentsSHA256 = strings.Repeat("e", 64)
	updated, err := AppendRule(p, second)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 1 || len(updated.Rules) != 2 || updated.PollMilliseconds != 250 || updated.CooldownSeconds != 90 {
		t.Fatalf("append mutated or lost policy settings: original=%+v updated=%+v", p, updated)
	}
	duplicate := base
	duplicate.Name = "duplicate"
	if _, err := AppendRule(p, duplicate); err == nil || !strings.Contains(err.Error(), "same authorization fingerprint") {
		t.Fatalf("expected duplicate-fingerprint rejection, got %v", err)
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add([]byte(`{"version":1,"account":"alice","rules":[{"name":"x","arguments_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","parent_executable":"/usr/bin/true","parent_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","parent_code_identifier":"com.apple.true","parent_cdhash":"dddddddddddddddddddddddddddddddddddddddd","auth_context_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}`))
	f.Add([]byte(`{"version":1,"version":2}`))
	f.Add([]byte(`{"rules":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decode(strings.NewReader(string(data)))
	})
}
