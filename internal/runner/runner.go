package runner

import (
	"context"
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/aiwaki/osaguard/internal/policy"
)

const PolicyPath = "/Library/Application Support/OsaGuard/policy.json"

func Run(actionName string) error {
	if os.Geteuid() != 0 {
		return errors.New("privileged-run must execute as root through the installed sudoers rule")
	}
	p, err := policy.Load(PolicyPath, true)
	if err != nil {
		return err
	}
	action, ok := p.Actions[actionName]
	if !ok {
		return fmt.Errorf("action %q is not allowed", actionName)
	}
	if err := policy.VerifyExecutable(action); err != nil {
		return fmt.Errorf("action %q executable failed trust checks: %w", actionName, err)
	}

	timeout := time.Duration(action.EffectiveTimeoutSeconds()) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	audit(actionName, "start", nil)
	cmd := command(ctx, action)
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("action exceeded %s timeout", timeout)
	}
	audit(actionName, "finish", err)
	return err
}

func command(ctx context.Context, action policy.Action) *exec.Cmd {
	cmd := exec.CommandContext(ctx, action.Executable, action.Arguments...)
	cmd.Dir = "/"
	cmd.Env = []string{
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	}
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func audit(action, phase string, runErr error) {
	w, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_NOTICE, "osaguard")
	if err != nil {
		return
	}
	defer w.Close()
	uid := os.Getenv("SUDO_UID")
	if _, err := strconv.ParseUint(uid, 10, 32); err != nil {
		uid = "unknown"
	}
	message := fmt.Sprintf("action=%s phase=%s invoking_uid=%s", action, phase, uid)
	if runErr != nil {
		message += " result=error error=" + runErr.Error()
	} else if phase == "finish" {
		message += " result=success"
	}
	_ = w.Notice(message)
}
