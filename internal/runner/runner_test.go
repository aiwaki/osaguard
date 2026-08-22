package runner

import (
	"context"
	"reflect"
	"testing"

	"github.com/aiwaki/osaguard/internal/policy"
)

func TestCommandUsesNoShellAndMinimalEnvironment(t *testing.T) {
	action := policy.Action{
		Executable: "/usr/bin/id",
		Arguments:  []string{"-u"},
	}
	cmd := command(context.Background(), action)
	if cmd.Path != action.Executable {
		t.Fatalf("unexpected path: %q", cmd.Path)
	}
	if !reflect.DeepEqual(cmd.Args, []string{"/usr/bin/id", "-u"}) {
		t.Fatalf("unexpected args: %#v", cmd.Args)
	}
	if cmd.Dir != "/" {
		t.Fatalf("unexpected working directory: %q", cmd.Dir)
	}
	wantEnv := []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	if !reflect.DeepEqual(cmd.Env, wantEnv) {
		t.Fatalf("unexpected environment: %#v", cmd.Env)
	}
}
