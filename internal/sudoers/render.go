package sudoers

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aiwaki/osaguard/internal/policy"
)

const RunnerPath = "/Library/Application Support/OsaGuard/osaguard-privileged"
const runnerSudoersPath = "/Library/Application\\ Support/OsaGuard/osaguard-privileged"

var userPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

func Render(p *policy.Policy, user string) (string, error) {
	if !userPattern.MatchString(user) {
		return "", fmt.Errorf("unsafe macOS user name %q", user)
	}
	if err := p.Validate(); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("# Managed by OsaGuard. Local edits are replaced on reinstall.\n")
	for _, name := range p.ActionNames() {
		b.WriteString(user)
		b.WriteString(" ALL=(root) NOPASSWD: NOSETENV: ")
		b.WriteString(runnerSudoersPath)
		b.WriteString(" privileged-run ")
		b.WriteString(name)
		b.WriteString("\n")
	}
	return b.String(), nil
}
