package policy

import (
	"os"
	"strings"
	"testing"
)

func TestDecodeValidPolicy(t *testing.T) {
	p, err := Decode(strings.NewReader(`{
  "version": 1,
  "actions": {
    "root-id": {
      "executable": "/usr/bin/id",
      "arguments": ["-u"],
      "timeout_seconds": 5
    }
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ActionNames(); len(got) != 1 || got[0] != "root-id" {
		t.Fatalf("unexpected names: %v", got)
	}
	if got := p.Actions["root-id"].EffectiveTimeoutSeconds(); got != 5 {
		t.Fatalf("unexpected timeout: %d", got)
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	_, err := Decode(strings.NewReader(`{"version":1,"actions":{"x":{"executable":"/usr/bin/id","surprise":true}}}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestDecodeRejectsDuplicateKeys(t *testing.T) {
	for _, input := range []string{
		`{"version":1,"version":1,"actions":{"x":{"executable":"/usr/bin/id"}}}`,
		`{"version":1,"actions":{"x":{"executable":"/usr/bin/id","executable":"/usr/bin/true"}}}`,
	} {
		_, err := Decode(strings.NewReader(input))
		if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
			t.Fatalf("expected duplicate-key error, got %v", err)
		}
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

func TestValidateRejectsGenericInterpreters(t *testing.T) {
	p := &Policy{Version: 1, Actions: map[string]Action{
		"shell": {Executable: "/bin/sh", Arguments: []string{"-c", "anything"}},
	}}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("expected forbidden-tool error, got %v", err)
	}
}

func TestValidateRequiresHashForNonSystemExecutable(t *testing.T) {
	p := &Policy{Version: 1, Actions: map[string]Action{
		"custom": {Executable: "/usr/local/libexec/custom-helper"},
	}}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("expected sha256 error, got %v", err)
	}
}

func TestActionNamesSorted(t *testing.T) {
	p := &Policy{Actions: map[string]Action{"z-last": {}, "a-first": {}}}
	got := p.ActionNames()
	if strings.Join(got, ",") != "a-first,z-last" {
		t.Fatalf("unexpected order: %v", got)
	}
}

func TestVerifyTrustedFileAcceptsRootOwnedSystemBinary(t *testing.T) {
	if err := VerifyTrustedFile("/usr/bin/id", true); err != nil {
		t.Fatalf("expected macOS system binary to pass trust checks: %v", err)
	}
}

func TestVerifyTrustedFileRejectsUserOwnedPath(t *testing.T) {
	path := t.TempDir() + "/helper"
	if err := os.WriteFile(path, []byte("test"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTrustedFile(path, true); err == nil || !strings.Contains(err.Error(), "not owned by root") {
		t.Fatalf("expected ownership rejection, got %v", err)
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add([]byte(`{"version":1,"actions":{"root-id":{"executable":"/usr/bin/id"}}}`))
	f.Add([]byte(`{"version":1,"version":2}`))
	f.Add([]byte(`{"actions":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decode(strings.NewReader(string(data)))
	})
}
