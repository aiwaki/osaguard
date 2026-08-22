package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/aiwaki/osaguard/internal/autotype"
	"github.com/aiwaki/osaguard/internal/darwinbridge"
	"github.com/aiwaki/osaguard/internal/policy"
	"github.com/aiwaki/osaguard/internal/processhardening"
	"github.com/aiwaki/osaguard/internal/runner"
	"github.com/aiwaki/osaguard/internal/secureenroll"
	"github.com/aiwaki/osaguard/internal/sudoers"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const version = "0.1.1"

func main() {
	// AppKit password enrollment must run on the primordial macOS UI thread.
	// main starts on that thread; keep it there for this short-lived helper and
	// for all other subcommands, which do not depend on thread migration.
	runtime.LockOSThread()
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "osaguard:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("this build is intended for macOS")
	}
	if len(args) == 0 {
		usage()
		return errors.New("missing command")
	}

	switch args[0] {
	case "version", "--version", "-version":
		fmt.Println(version)
		return nil
	case "validate-policy":
		return validatePolicy(args[1:])
	case "render-sudoers":
		return renderSudoers(args[1:])
	case "run":
		return clientRun(args[1:])
	case "privileged-run":
		if len(args) != 2 {
			return errors.New("usage: osaguard privileged-run <action>")
		}
		return runner.Run(args[1])
	case "list":
		return listActions()
	case "inspect-auth":
		return inspectAuth()
	case "request-accessibility":
		return requestAccessibility()
	case "accessibility-status":
		return accessibilityStatus(args[1:])
	case "auth-dialog-status":
		return authDialogStatus(args[1:])
	case "fingerprint-current":
		return fingerprintCurrent(args[1:])
	case "enroll-next":
		return enrollNext(args[1:])
	case "validate-autotype-policy":
		return validateAutotypePolicy(args[1:])
	case "install-autotype-policy":
		return installAutotypePolicy(args[1:])
	case "store-password":
		return storePassword(args[1:])
	case "store-password-gui":
		return storePasswordGUI(args[1:])
	case "password-status":
		return passwordStatus(args[1:])
	case "forget-password":
		return forgetPassword(args[1:])
	case "watch":
		return watch(args[1:])
	case "autotype-status":
		return autotypeStatus(args[1:])
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func validatePolicy(args []string) error {
	fs := flag.NewFlagSet("validate-policy", flag.ContinueOnError)
	path := fs.String("policy", "", "path to policy JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || fs.NArg() != 0 {
		return errors.New("usage: osaguard validate-policy --policy <path>")
	}
	p, err := policy.Load(*path, false)
	if err != nil {
		return err
	}
	for _, name := range p.ActionNames() {
		if err := policy.VerifyExecutable(p.Actions[name]); err != nil {
			return fmt.Errorf("action %q: %w", name, err)
		}
	}
	fmt.Printf("policy valid: %d action(s)\n", len(p.Actions))
	return nil
}

func renderSudoers(args []string) error {
	fs := flag.NewFlagSet("render-sudoers", flag.ContinueOnError)
	path := fs.String("policy", "", "path to policy JSON")
	user := fs.String("user", "", "local macOS user allowed to run actions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *user == "" || fs.NArg() != 0 {
		return errors.New("usage: osaguard render-sudoers --policy <path> --user <name>")
	}
	p, err := policy.Load(*path, false)
	if err != nil {
		return err
	}
	text, err := sudoers.Render(p, *user)
	if err != nil {
		return err
	}
	fmt.Print(text)
	return nil
}

func clientRun(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: osaguard run <action>")
	}
	cmd := exec.Command("/usr/bin/sudo", "-n", "--", sudoers.RunnerPath, "privileged-run", args[0])
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("action failed (or OsaGuard is not installed for this exact action): %w", err)
	}
	return nil
}

func listActions() error {
	p, err := policy.Load(runner.PolicyPath, true)
	if err != nil {
		return err
	}
	for _, name := range p.ActionNames() {
		action := p.Actions[name]
		if action.Description != "" {
			fmt.Printf("%s\t%s\n", name, action.Description)
		} else {
			fmt.Println(name)
		}
	}
	return nil
}

func inspectAuth() error {
	snapshot, err := darwinbridge.ReadAuthSnapshot()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func requestAccessibility() error {
	trusted, err := darwinbridge.RequestAccessibility()
	if err != nil {
		return err
	}
	if trusted {
		fmt.Println("Accessibility permission is already granted")
	} else {
		fmt.Println("Enable OsaGuard in System Settings → Privacy & Security → Accessibility, then restart the watcher")
	}
	return nil
}

func accessibilityStatus(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: osaguard accessibility-status")
	}
	fmt.Println(accessibilityStatusLine(darwinbridge.AccessibilityTrusted()))
	return nil
}

func accessibilityStatusLine(trusted bool) string {
	return fmt.Sprintf("accessibility=%t", trusted)
}

func fingerprintCurrent(args []string) error {
	fs := flag.NewFlagSet("fingerprint-current", flag.ContinueOnError)
	name := fs.String("name", "approved-script", "short name for the generated rule")
	account := fs.String("account", os.Getenv("USER"), "Keychain account label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: osaguard fingerprint-current [--name <rule>] [--account <label>]")
	}
	processes, err := darwinbridge.ListOsaScripts(uint32(os.Getuid()))
	if err != nil {
		return err
	}
	if len(processes) != 1 {
		return fmt.Errorf("exactly one newly opened osascript process is required; found %d", len(processes))
	}
	fingerprint, err := autotype.FingerprintProcess(processes[0])
	if err != nil {
		return err
	}
	snapshot, err := darwinbridge.ReadAuthSnapshot()
	if err != nil {
		return err
	}
	if !snapshot.IsAuthDialog || !snapshot.AuthContextComplete || snapshot.AuthContextSHA256 == "" {
		return errors.New("an approved Apple authorization dialog with one focused secure field must be visible")
	}
	rule := autotype.SuggestedRule(*name, fingerprint, snapshot.AuthContextSHA256)
	data, err := autotype.MarshalSuggestedPolicy(*account, []autotype.Rule{rule})
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

type enrollmentBridge struct{}

func (enrollmentBridge) ListOsaScripts(uid uint32) ([]darwinbridge.ProcessInfo, error) {
	return darwinbridge.ListOsaScripts(uid)
}

func (enrollmentBridge) ReadAuthSnapshot() (darwinbridge.AuthSnapshot, error) {
	return darwinbridge.ReadAuthSnapshot()
}

func enrollNext(args []string) error {
	fs := flag.NewFlagSet("enroll-next", flag.ContinueOnError)
	name := fs.String("name", "approved-script", "short name for the generated rule")
	account := fs.String("account", os.Getenv("USER"), "Keychain account label")
	output := fs.String("output", "", "new policy path, or - for stdout")
	appendTo := fs.String("append-to", "", "privately and atomically append to an existing draft policy")
	timeoutSeconds := fs.Int("timeout-seconds", 120, "bounded wait for the next request")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *name == "" || *account == "" || *timeoutSeconds < 10 || *timeoutSeconds > 300 || (*output != "" && *appendTo != "") {
		return errors.New("usage: osaguard enroll-next [--name <rule>] [--account <label>] [--output <new-path>|--append-to <draft-policy>] [--timeout-seconds 10..300]")
	}
	if *output == "" && *appendTo == "" {
		*output = "./autotype-policy.json"
	}

	var draft *enrollmentDraft
	if *appendTo != "" {
		var err error
		draft, err = loadEnrollmentDraft(*appendTo, uint32(os.Getuid()))
		if err != nil {
			return err
		}
		if draft.policy.Account != *account {
			return fmt.Errorf("draft policy account %q does not match requested account %q", draft.policy.Account, *account)
		}
		for _, rule := range draft.policy.Rules {
			if rule.Name == *name {
				return fmt.Errorf("draft policy already contains rule name %q", *name)
			}
		}
	} else if *output != "-" {
		if _, err := os.Lstat(*output); err == nil {
			return fmt.Errorf("refusing to overwrite existing enrollment output %q", *output)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect enrollment output path: %w", err)
		}
	}

	snapshot, err := darwinbridge.ReadAuthSnapshot()
	if err != nil {
		return fmt.Errorf("check Accessibility: %w", err)
	}
	if !snapshot.AccessibilityTrusted {
		if _, err := darwinbridge.RequestAccessibility(); err != nil {
			return fmt.Errorf("request Accessibility: %w", err)
		}
		return errors.New("grant Accessibility to OsaGuard in Privacy & Security, then run enroll-next again")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(*timeoutSeconds)*time.Second)
	defer cancel()
	fmt.Fprintf(os.Stderr, "Waiting up to %d seconds for one new osascript authorization dialog; trigger the real operation now.\n", *timeoutSeconds)
	result, err := autotype.WaitForEnrollment(ctx, enrollmentBridge{}, autotype.EnrollmentOptions{
		UID: uint32(os.Getuid()), PollInterval: 200 * time.Millisecond, StableChecks: 3,
	})
	if err != nil {
		return err
	}
	rule := autotype.SuggestedRule(*name, result.Fingerprint, result.Snapshot.AuthContextSHA256)
	var data []byte
	if draft != nil {
		current, err := loadEnrollmentDraft(*appendTo, uint32(os.Getuid()))
		if err != nil {
			return fmt.Errorf("recheck draft before append: %w", err)
		}
		if current.device != draft.device || current.inode != draft.inode || !bytes.Equal(current.data, draft.data) {
			return errors.New("draft policy changed while enrollment was waiting; refusing to overwrite it")
		}
		updated, err := autotype.AppendRule(draft.policy, rule)
		if err != nil {
			return err
		}
		data, err = autotype.MarshalPolicy(updated)
		if err != nil {
			return err
		}
		if err := replaceEnrollmentDraft(*appendTo, data); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Captured rule %q and atomically appended it to %s; complete the current password dialog normally.\n", *name, *appendTo)
		return nil
	}
	data, err = autotype.MarshalSuggestedPolicy(*account, []autotype.Rule{rule})
	if err != nil {
		return err
	}
	if *output == "-" {
		if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
			return err
		}
		return nil
	}
	if err := writeEnrollmentPolicy(*output, data); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Captured rule %q without reading or typing a password; review %s and complete the current password dialog normally.\n", *name, *output)
	return nil
}

type enrollmentDraft struct {
	policy *autotype.Policy
	data   []byte
	device uint64
	inode  uint64
}

func loadEnrollmentDraft(path string, ownerUID uint32) (*enrollmentDraft, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open private enrollment draft without following symlinks: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open enrollment draft file descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || uint32(stat.Uid) != ownerUID || uint64(stat.Nlink) != 1 || info.Mode().Perm() != 0600 {
		return nil, errors.New("enrollment draft must be a regular, single-link, mode-0600 file owned by the current user")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(autotype.MaxPolicyBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > autotype.MaxPolicyBytes {
		return nil, fmt.Errorf("enrollment draft exceeds %d bytes", autotype.MaxPolicyBytes)
	}
	policy, err := autotype.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return &enrollmentDraft{policy: policy, data: data, device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func replaceEnrollmentDraft(path string, data []byte) (err error) {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".osaguard-policy-*")
	if err != nil {
		return fmt.Errorf("create draft update: %w", err)
	}
	tempPath := temp.Name()
	complete := false
	defer func() {
		if !complete {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0600); err != nil {
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("atomically replace enrollment draft: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	if err := dir.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func writeEnrollmentPolicy(path string, data []byte) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create enrollment policy without overwriting an existing file: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func validateAutotypePolicy(args []string) error {
	fs := flag.NewFlagSet("validate-autotype-policy", flag.ContinueOnError)
	path := fs.String("policy", "", "path to autotype policy JSON")
	expectAccount := fs.String("expect-account", "", "require the policy Keychain account to match")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || fs.NArg() != 0 {
		return errors.New("usage: osaguard validate-autotype-policy --policy <path>")
	}
	p, err := autotype.Load(*path, false)
	if err != nil {
		return err
	}
	if *expectAccount != "" && p.Account != *expectAccount {
		return fmt.Errorf("autotype policy account %q does not match installation user %q", p.Account, *expectAccount)
	}
	fmt.Printf("autotype policy valid: %d rule(s)\n", len(p.Rules))
	return nil
}

func installAutotypePolicy(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("install-autotype-policy must run through sudo")
	}
	fs := flag.NewFlagSet("install-autotype-policy", flag.ContinueOnError)
	source := fs.String("source", "", "private user-owned draft policy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || fs.NArg() != 0 {
		return errors.New("usage: sudo osaguard install-autotype-policy --source <draft-policy>")
	}

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" || sudoUser == "root" {
		return errors.New("refusing missing or root SUDO_USER")
	}
	sudoUIDValue, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	if err != nil || sudoUIDValue == 0 {
		return errors.New("refusing missing or invalid SUDO_UID")
	}
	account, err := user.Lookup(sudoUser)
	if err != nil || account.Uid != strconv.FormatUint(sudoUIDValue, 10) {
		return errors.New("SUDO_USER and SUDO_UID do not identify the same local account")
	}

	draft, err := loadEnrollmentDraft(*source, uint32(sudoUIDValue))
	if err != nil {
		return err
	}
	if draft.policy.Account != sudoUser {
		return fmt.Errorf("draft policy account %q does not match sudo user %q", draft.policy.Account, sudoUser)
	}
	installed, err := autotype.Load(autotype.PolicyPath, true)
	if err != nil {
		return fmt.Errorf("load existing root-owned policy; install OsaGuard first: %w", err)
	}
	if installed.Account != sudoUser {
		return fmt.Errorf("installed policy account %q does not match sudo user %q", installed.Account, sudoUser)
	}
	data, err := autotype.MarshalPolicy(draft.policy)
	if err != nil {
		return err
	}
	if err := replaceInstalledAutotypePolicy(data); err != nil {
		return err
	}

	uid := strconv.FormatUint(sudoUIDValue, 10)
	restart := exec.Command("/bin/launchctl", "kickstart", "-k", "gui/"+uid+"/dev.aiwaki.osaguard.autotype")
	restart.Env = []string{}
	if output, err := restart.CombinedOutput(); err != nil {
		return fmt.Errorf("policy installed, but restart watcher manually: %w: %s", err, strings.TrimSpace(string(output)))
	}
	fmt.Printf("installed %d autotype rule(s) and restarted the watcher without replacing the app binary\n", len(draft.policy.Rules))
	return nil
}

func replaceInstalledAutotypePolicy(data []byte) (err error) {
	directory := filepath.Dir(autotype.PolicyPath)
	temp, err := os.CreateTemp(directory, ".autotype-policy-*")
	if err != nil {
		return fmt.Errorf("create root policy update: %w", err)
	}
	tempPath := temp.Name()
	complete := false
	defer func() {
		if !complete {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0644); err != nil {
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if _, err := autotype.Load(tempPath, true); err != nil {
		return fmt.Errorf("validate staged root policy: %w", err)
	}
	if err := os.Rename(tempPath, autotype.PolicyPath); err != nil {
		return fmt.Errorf("atomically install root policy: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	if err := dir.Close(); err != nil {
		return err
	}
	if _, err := autotype.Load(autotype.PolicyPath, true); err != nil {
		return fmt.Errorf("verify installed root policy: %w", err)
	}
	complete = true
	return nil
}

func storePassword(args []string) error {
	fs := flag.NewFlagSet("store-password", flag.ContinueOnError)
	account := fs.String("account", os.Getenv("USER"), "Keychain account label matching the autotype policy")
	ack := fs.Bool("acknowledge-risk", false, "acknowledge that unattended password retrieval weakens account security")
	singleEntry := fs.Bool("single-entry", false, "store after one no-echo entry instead of typo-check confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*ack || !validAccountLabel(*account) || fs.NArg() != 0 {
		return errors.New("usage: osaguard store-password --account <label> --acknowledge-risk [--single-entry]")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("password enrollment requires an interactive terminal")
	}
	if err := hardenBeforePasswordEntry(hardenPasswordProcess); err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "Administrator password (stored in macOS Keychain): ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	defer wipe(first)
	if len(first) == 0 || len(first) > 1024 || !utf8.Valid(first) || containsForbiddenSecretByte(first) {
		return errors.New("password must be valid UTF-8, contain no line breaks, and be 1 to 1024 bytes")
	}
	if !*singleEntry {
		fmt.Fprint(os.Stderr, "Repeat password: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		defer wipe(second)
		if len(first) != len(second) || subtle.ConstantTimeCompare(first, second) != 1 {
			return errors.New("passwords do not match")
		}
	}
	if err := darwinbridge.KeychainStore(*account, first); err != nil {
		return err
	}
	fmt.Println("password stored in macOS Keychain; plaintext was not written to disk")
	return nil
}

// hardenPasswordProcess is overridden only by in-package tests. It must run
// before a terminal read can place an administrator password in this process.
var hardenPasswordProcess = processhardening.Harden

func hardenBeforePasswordEntry(harden func() error) error {
	if harden == nil {
		return errors.New("password process hardening is unavailable")
	}
	if err := harden(); err != nil {
		return fmt.Errorf("harden password process: %w", err)
	}
	return nil
}

const (
	passwordActionSaved     = "saved"
	passwordActionCancelled = "cancelled"
)

type passwordGUIActions struct {
	harden func() error
	prompt func(string) ([]byte, error)
	store  func(string, []byte) error
	lock   func([]byte) error
	unlock func([]byte) error
}

var nativePasswordGUIActions = passwordGUIActions{
	harden: processhardening.Harden,
	prompt: darwinbridge.PromptPassword,
	store:  darwinbridge.KeychainStore,
	lock:   unix.Mlock,
	unlock: unix.Munlock,
}

func storePasswordGUI(args []string) error {
	action, err := runStorePasswordGUI(args, nativePasswordGUIActions)
	if err != nil {
		return err
	}
	fmt.Println(passwordActionLine(action))
	return nil
}

func runStorePasswordGUI(args []string, actions passwordGUIActions) (string, error) {
	fs := flag.NewFlagSet("store-password-gui", flag.ContinueOnError)
	account := fs.String("account", os.Getenv("USER"), "Keychain account label")
	ack := fs.Bool("acknowledge-risk", false, "acknowledge universal passwordless administrator risk")
	locale := fs.String("locale", "system", "dialog locale: system, ru, or en")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if !*ack || fs.NArg() != 0 || !validAccountLabel(*account) ||
		(*locale != "system" && *locale != "ru" && *locale != "en") {
		return "", errors.New("usage: osaguard store-password-gui --account <label> --acknowledge-risk [--locale system|ru|en]")
	}
	outcome, err := secureenroll.Run(*account, *locale, secureenroll.Actions{
		Harden: actions.harden,
		Prompt: actions.prompt,
		Store:  actions.store,
		Lock:   actions.lock,
		Unlock: actions.unlock,
	})
	return string(outcome), err
}

func passwordActionLine(action string) string {
	return "password_action=" + action
}

func authDialogStatus(args []string) error {
	fs := flag.NewFlagSet("auth-dialog-status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: osaguard auth-dialog-status")
	}
	snapshot, err := darwinbridge.ReadAuthSnapshot()
	if err != nil {
		return err
	}
	fmt.Println(authDialogStatusLine(snapshot.IsAuthDialog))
	return nil
}

func authDialogStatusLine(active bool) string {
	return fmt.Sprintf("auth_dialog_active=%t", active)
}

func passwordStatus(args []string) error {
	fs := flag.NewFlagSet("password-status", flag.ContinueOnError)
	account := fs.String("account", os.Getenv("USER"), "Keychain account label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !validAccountLabel(*account) {
		return errors.New("usage: osaguard password-status --account <label>")
	}
	exists, err := darwinbridge.KeychainExists(*account)
	if err != nil {
		return err
	}
	fmt.Println(passwordStatusLine(exists))
	return nil
}

func passwordStatusLine(exists bool) string {
	return fmt.Sprintf("password_saved=%t", exists)
}

func validAccountLabel(account string) bool {
	return secureenroll.ValidAccount(account)
}

func containsForbiddenSecretByte(value []byte) bool {
	return secureenroll.ContainsForbiddenSecretByte(value)
}

func forgetPassword(args []string) error {
	fs := flag.NewFlagSet("forget-password", flag.ContinueOnError)
	// Keep parsing the legacy flag solely to return an explicit migration error.
	// Silently treating it as a targeted deletion would leave another OsaGuard
	// password record behind, while silently ignoring it would delete more than
	// the caller asked for.
	fs.String("account", "", "deprecated; removal clears every OsaGuard password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: osaguard forget-password")
	}
	if flagWasSet(fs, "account") {
		return errors.New("forget-password removes every saved OsaGuard password; do not pass --account")
	}
	if err := deleteAllOsaGuardPasswords(); err != nil {
		return err
	}
	fmt.Println("all saved OsaGuard passwords removed from macOS Keychain")
	return nil
}

// deleteAllOsaGuardPasswords is replaced only by unit tests. The native
// implementation scopes deletion to OsaGuard's dedicated Keychain service and
// does not alter the user's Keychain search list or default Keychain.
var deleteAllOsaGuardPasswords = darwinbridge.KeychainDeleteAll

func watch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	path := fs.String("policy", autotype.PolicyPath, "path to root-owned autotype policy")
	universal := fs.Bool("universal", false, "approve every new /usr/bin/osascript administrator request")
	account := fs.String("account", os.Getenv("USER"), "Keychain account label; universal mode only")
	dryRun := fs.Bool("dry-run", false, "recognize matching dialogs but never retrieve or type the password")
	unsafePolicy := fs.Bool("allow-untrusted-policy-for-testing", false, "allow a user-owned policy; valid only with --dry-run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	policySet, accountSet := flagWasSet(fs, "policy"), flagWasSet(fs, "account")
	if fs.NArg() != 0 || (*unsafePolicy && !*dryRun) ||
		(*universal && (policySet || *unsafePolicy)) || (!*universal && accountSet) ||
		(*universal && !validAccountLabel(*account)) {
		return errors.New("usage: osaguard watch (--universal --account <label> | [--policy <path>]) [--dry-run] [--allow-untrusted-policy-for-testing]")
	}
	var p *autotype.Policy
	var err error
	if *universal {
		p = autotype.NewUniversalPolicy(*account)
	} else {
		p, err = autotype.Load(*path, !*unsafePolicy)
		if err != nil {
			return err
		}
	}
	watcher, err := autotype.NewWatcher(p, autotype.WatchOptions{DryRun: *dryRun, Logger: log.New(os.Stderr, "osaguard: ", log.LstdFlags)})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = watcher.Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func autotypeStatus(args []string) error {
	fs := flag.NewFlagSet("autotype-status", flag.ContinueOnError)
	path := fs.String("policy", autotype.PolicyPath, "path to root-owned autotype policy")
	universal := fs.Bool("universal", false, "report universal-mode readiness")
	account := fs.String("account", os.Getenv("USER"), "Keychain account label; universal mode only")
	metadataOnly := fs.Bool("metadata-only", false, "verify Keychain item presence without retrieving password bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	policySet, accountSet := flagWasSet(fs, "policy"), flagWasSet(fs, "account")
	if fs.NArg() != 0 || (*universal && policySet) || (!*universal && accountSet) ||
		(*universal && !validAccountLabel(*account)) {
		return errors.New("usage: osaguard autotype-status (--universal --account <label> | [--policy <path>]) [--metadata-only]")
	}
	mode := "exact"
	risk := "enrolled_rules_only"
	var p *autotype.Policy
	var err error
	if *universal {
		mode = "universal"
		risk = "passwordless_admin_for_any_same_user_process"
		p = autotype.NewUniversalPolicy(*account)
		if err := p.Validate(); err != nil {
			return err
		}
	} else {
		p, err = autotype.Load(*path, true)
		if err != nil {
			return fmt.Errorf("policy: %w", err)
		}
	}
	accessibility := darwinbridge.AccessibilityTrusted()
	unlocked := darwinbridge.SessionUnlocked()
	keychainState := "readable"
	exists, err := darwinbridge.KeychainExists(p.Account)
	if err != nil {
		return fmt.Errorf("Keychain password metadata: %w", err)
	}
	if !exists {
		keychainState = "missing"
	} else if *metadataOnly {
		keychainState = "present"
	} else {
		secret, err := darwinbridge.KeychainLoad(p.Account)
		if err != nil {
			return fmt.Errorf("Keychain password: %w", err)
		}
		wipe(secret)
	}
	fmt.Printf("autotype_mode=%s rules=%d accessibility=%t session_unlocked=%t password_saved=%t keychain_password=%s risk=%s\n",
		mode, len(p.Rules), accessibility, unlocked, exists, keychainState, risk)
	if !accessibility || !unlocked || !exists {
		return errors.New("autotype prerequisites are not all active")
	}
	return nil
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func wipe(value []byte) {
	secureenroll.Wipe(value)
}

func usage() {
	fmt.Print(`OsaGuard can execute fixed privileged actions or automatically approve AppleScript administrator dialogs.

SECURITY WARNING: --universal gives every process running in your account a route to passwordless administrator approval.

Usage:
  osaguard validate-policy --policy <path>
  osaguard render-sudoers --policy <path> --user <name>
  osaguard run <action>
  osaguard list
  osaguard inspect-auth
  osaguard request-accessibility
  osaguard accessibility-status
  osaguard auth-dialog-status
  osaguard enroll-next --name <rule> [--output <new-path>|--append-to <draft>]
  osaguard fingerprint-current --name <rule>
  osaguard validate-autotype-policy --policy <path>
  sudo osaguard install-autotype-policy --source <draft-policy>
  osaguard store-password --account <label> --acknowledge-risk [--single-entry]
  osaguard store-password-gui --account <label> --acknowledge-risk [--locale system|ru|en]
  osaguard password-status --account <label>
  osaguard forget-password
  osaguard watch (--universal --account <label> | [--policy <path>]) [--dry-run]
  osaguard autotype-status (--universal --account <label> | [--policy <path>]) [--metadata-only]
  osaguard version
`)
}
