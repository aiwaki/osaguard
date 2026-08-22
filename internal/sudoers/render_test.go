package sudoers

import (
	"strings"
	"testing"

	"github.com/aiwaki/osaguard/internal/policy"
)

func TestRenderUsesExactActionCommands(t *testing.T) {
	p := &policy.Policy{Version: 1, Actions: map[string]policy.Action{
		"z-last":  {Executable: "/usr/bin/id"},
		"a-first": {Executable: "/usr/bin/true"},
	}}
	got, err := Render(p, "alice")
	if err != nil {
		t.Fatal(err)
	}
	first := "alice ALL=(root) NOPASSWD: NOSETENV: " + runnerSudoersPath + " privileged-run a-first"
	last := "alice ALL=(root) NOPASSWD: NOSETENV: " + runnerSudoersPath + " privileged-run z-last"
	if strings.Index(got, first) < 0 || strings.Index(got, first) >= strings.Index(got, last) {
		t.Fatalf("missing sorted exact rules:\n%s", got)
	}
	if strings.Contains(got, "*") {
		t.Fatalf("sudoers must not contain wildcards:\n%s", got)
	}
}

func TestRenderRejectsUnsafeUser(t *testing.T) {
	p := &policy.Policy{Version: 1, Actions: map[string]policy.Action{
		"root-id": {Executable: "/usr/bin/id"},
	}}
	if _, err := Render(p, "alice ALL=(ALL) ALL"); err == nil {
		t.Fatal("expected unsafe user name to be rejected")
	}
}
