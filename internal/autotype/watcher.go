package autotype

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
	"unicode/utf8"

	"github.com/aiwaki/makc"
	"github.com/aiwaki/osaguard/internal/darwinbridge"
	"github.com/aiwaki/osaguard/internal/processhardening"
	"golang.org/x/sys/unix"
)

type WatchOptions struct {
	DryRun bool
	Logger *log.Logger
	driver Driver
}

type Driver interface {
	ListOsaScripts(uid uint32) ([]darwinbridge.ProcessInfo, error)
	SessionUnlocked() bool
	ReadAuthSnapshot() (darwinbridge.AuthSnapshot, error)
	KeychainLoad(account string) ([]byte, error)
	InjectUTF8ToPID(pid int, secret []byte) error
	InjectReturnToPID(pid int, expectedLength int) error
	EmergencyStopHeld(ctx context.Context) (bool, error)
}

type systemDriver struct{}

func (systemDriver) ListOsaScripts(uid uint32) ([]darwinbridge.ProcessInfo, error) {
	return darwinbridge.ListOsaScripts(uid)
}
func (systemDriver) SessionUnlocked() bool { return darwinbridge.SessionUnlocked() }
func (systemDriver) ReadAuthSnapshot() (darwinbridge.AuthSnapshot, error) {
	return darwinbridge.ReadAuthSnapshot()
}
func (systemDriver) KeychainLoad(account string) ([]byte, error) {
	return darwinbridge.KeychainLoad(account)
}
func (systemDriver) InjectUTF8ToPID(pid int, secret []byte) error {
	return darwinbridge.InjectUTF8ToPID(pid, secret)
}
func (systemDriver) InjectReturnToPID(pid int, expectedLength int) error {
	return darwinbridge.InjectReturnToPID(pid, expectedLength)
}
func (systemDriver) EmergencyStopHeld(ctx context.Context) (bool, error) {
	client, err := makc.Open()
	if err != nil {
		return false, err
	}
	defer client.Close()
	return client.Keyboard.Down(ctx, makc.KeyEscape)
}

type observedProcess struct {
	startSeconds  int64
	firstSeen     time.Time
	handled       bool
	fingerprinted bool
	rule          *Rule
}

type Watcher struct {
	policy              *Policy
	options             WatchOptions
	driver              Driver
	observed            map[int]*observedProcess
	observedAuthTargets map[authTargetKey]struct{}
	lastType            time.Time
}

type authTargetKey struct {
	pid               int
	startSeconds      int64
	startMicroseconds int64
	contextSHA256     string
}

const securityAgentPath = "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent"

func NewWatcher(policy *Policy, options WatchOptions) (*Watcher, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if options.Logger == nil {
		options.Logger = log.New(os.Stderr, "osaguard: ", log.LstdFlags)
	}
	if options.driver == nil {
		options.driver = systemDriver{}
	}
	return &Watcher{
		policy: policy, options: options, driver: options.driver,
		observed: make(map[int]*observedProcess), observedAuthTargets: make(map[authTargetKey]struct{}),
	}, nil
}

func (w *Watcher) Run(ctx context.Context) error {
	if runtime.GOOS != "darwin" {
		return errors.New("autotype watcher requires macOS")
	}
	if !w.options.DryRun {
		if err := processhardening.Harden(); err != nil {
			return err
		}
	}
	initial, err := w.driver.ListOsaScripts(uint32(os.Getuid()))
	if err != nil {
		return err
	}
	now := time.Now()
	for _, process := range initial {
		w.observed[process.PID] = &observedProcess{startSeconds: process.StartSeconds, firstSeen: now, handled: true}
	}
	initialAuth, err := w.driver.ReadAuthSnapshot()
	if err != nil {
		return fmt.Errorf("inspect authorization UI at watcher start: %w", err)
	}
	w.rememberAuthTarget(initialAuth)
	if w.policy.IsUniversal() {
		w.options.Logger.Print("WARNING: UNIVERSAL MODE IS ACTIVE: any process running as this user can trigger passwordless administrator approval through /usr/bin/osascript; existing processes ignored")
	} else {
		w.options.Logger.Printf("watching for %d approved osascript rule(s); existing processes ignored", len(w.policy.Rules))
	}

	ticker := time.NewTicker(time.Duration(w.policy.EffectivePollMilliseconds()) * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := w.poll(ctx); err != nil {
				w.options.Logger.Printf("poll rejected: %v", err)
			}
		}
	}
}

func (w *Watcher) poll(ctx context.Context) error {
	if !w.driver.SessionUnlocked() {
		return nil
	}
	processes, err := w.driver.ListOsaScripts(uint32(os.Getuid()))
	if err != nil {
		return err
	}
	alive := make(map[int]struct{}, len(processes))
	for _, process := range processes {
		alive[process.PID] = struct{}{}
	}
	for pid := range w.observed {
		if _, ok := alive[pid]; !ok {
			delete(w.observed, pid)
		}
	}
	newlyObserved := make(map[int]struct{})
	for _, process := range processes {
		observed, known := w.observed[process.PID]
		if !known || observed.startSeconds != process.StartSeconds {
			w.observed[process.PID] = &observedProcess{startSeconds: process.StartSeconds, firstSeen: time.Now()}
			newlyObserved[process.PID] = struct{}{}
		}
	}

	currentAuth, err := w.driver.ReadAuthSnapshot()
	if err != nil {
		for pid := range newlyObserved {
			w.observed[pid].handled = true
		}
		return fmt.Errorf("inspect authorization UI before process correlation: %w", err)
	}
	currentAuthWasObserved := w.authTargetWasObserved(currentAuth)
	w.rememberAuthTarget(currentAuth)
	if currentAuthWasObserved {
		for pid := range newlyObserved {
			w.observed[pid].handled = true
			w.options.Logger.Printf("pid %d rejected: authorization target was already visible before this osascript was observed", pid)
		}
	}

	for _, process := range processes {
		observed := w.observed[process.PID]
		if observed.handled {
			continue
		}
		if !observed.fingerprinted {
			rule, err := w.policy.Match(process)
			observed.fingerprinted = true
			if err != nil {
				observed.handled = true
				return fmt.Errorf("pid %d fingerprint: %w", process.PID, err)
			}
			observed.rule = rule
			if rule == nil {
				observed.handled = true
				continue
			}
		}
		if time.Since(observed.firstSeen) > time.Duration(w.policy.EffectiveProcessMaxAgeSeconds())*time.Second {
			observed.handled = true
			continue
		}
		if w.policy.RequiresSingleOsaScriptProcess() && len(processes) != 1 {
			return nil
		}
		if time.Since(w.lastType) < time.Duration(w.policy.EffectiveCooldownSeconds())*time.Second {
			return nil
		}
		if err := w.confirmAndType(ctx, process, *observed.rule); err != nil {
			return err
		}
		observed.handled = true
		w.lastType = time.Now()
	}
	return nil
}

func (w *Watcher) authTargetWasObserved(snapshot darwinbridge.AuthSnapshot) bool {
	key, ok := authTargetIdentity(snapshot)
	if !ok {
		return false
	}
	_, ok = w.observedAuthTargets[key]
	return ok
}

func (w *Watcher) rememberAuthTarget(snapshot darwinbridge.AuthSnapshot) {
	key, ok := authTargetIdentity(snapshot)
	if !ok {
		return
	}
	if len(w.observedAuthTargets) >= 128 {
		clear(w.observedAuthTargets)
	}
	w.observedAuthTargets[key] = struct{}{}
}

func authTargetIdentity(snapshot darwinbridge.AuthSnapshot) (authTargetKey, bool) {
	if !eligibleAuthSnapshot(snapshot) {
		return authTargetKey{}, false
	}
	return authTargetKey{
		pid: snapshot.PID, startSeconds: snapshot.StartSeconds,
		startMicroseconds: snapshot.StartMicroseconds, contextSHA256: snapshot.AuthContextSHA256,
	}, true
}

func eligibleAuthSnapshot(snapshot darwinbridge.AuthSnapshot) bool {
	return snapshot.AccessibilityTrusted && snapshot.IsAuthDialog && snapshot.AppleSigned && snapshot.AppFrontmost &&
		snapshot.AppOnscreen && snapshot.FocusedEnabled &&
		snapshot.PID > 0 && snapshot.StartSeconds > 0 && snapshot.StartMicroseconds >= 0 &&
		snapshot.CodeIdentifier == "com.apple.SecurityAgent" && snapshot.ExecutablePath == securityAgentPath &&
		snapshot.FocusedRole == "AXTextField" && snapshot.FocusedSubrole == "AXSecureTextField" &&
		snapshot.AuthContextComplete && len(snapshot.AuthContextSHA256) == 64 && snapshot.SecureFieldCount == 1
}

func (w *Watcher) confirmAndType(ctx context.Context, process darwinbridge.ProcessInfo, rule Rule) error {
	poll := time.Duration(w.policy.EffectivePollMilliseconds()) * time.Millisecond
	var stable darwinbridge.AuthSnapshot
	expectedAuthContext := rule.AuthContextSHA256
	for i := 0; i < w.policy.EffectiveStableChecks(); i++ {
		snapshot, err := w.driver.ReadAuthSnapshot()
		if err != nil {
			return err
		}
		if !snapshot.AccessibilityTrusted {
			return errors.New("Accessibility permission is not granted")
		}
		if !snapshot.IsAuthDialog {
			return errors.New("focused UI is not an approved Apple secure authorization field")
		}
		if !eligibleAuthSnapshot(snapshot) {
			return errors.New("authorization UI is unsupported, ambiguous, backgrounded, or changed process generation")
		}
		if snapshot.FocusedValueLength != 0 {
			return errors.New("authorization password field is not empty")
		}
		if rule.universalRequest && expectedAuthContext == "" {
			if !snapshot.AuthContextComplete || len(snapshot.AuthContextSHA256) != 64 {
				return errors.New("authorization dialog context is incomplete")
			}
			expectedAuthContext = snapshot.AuthContextSHA256
		}
		if snapshot.AuthContextSHA256 != expectedAuthContext {
			if rule.universalRequest {
				return errors.New("authorization dialog context changed during this universal request")
			}
			return errors.New("authorization dialog context does not match the enrolled rule")
		}
		if i > 0 && !sameAuthTarget(stable, snapshot) {
			return errors.New("authorization target changed during stability checks")
		}
		stable = snapshot
		if i+1 < w.policy.EffectiveStableChecks() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(poll):
			}
		}
	}

	if w.options.DryRun {
		w.options.Logger.Printf("DRY RUN: would type for rule=%s osascript_pid=%d auth_pid=%d identifier=%s", rule.Name, process.PID, stable.PID, stable.CodeIdentifier)
		return nil
	}
	if err := w.confirmOsaScriptStillEligible(process, rule); err != nil {
		return err
	}
	stop, err := w.driver.EmergencyStopHeld(ctx)
	if err != nil {
		return fmt.Errorf("check makc Escape interlock: %w", err)
	}
	if stop {
		return errors.New("Escape emergency stop is held; password injection suppressed")
	}
	secret, err := w.driver.KeychainLoad(w.policy.Account)
	if err != nil {
		return err
	}
	if err := unix.Mlock(secret); err != nil {
		zero(secret)
		return fmt.Errorf("lock password memory: %w", err)
	}
	defer func() {
		zero(secret)
		_ = unix.Munlock(secret)
	}()
	if len(secret) == 0 || len(secret) > 1024 {
		return errors.New("stored password length is outside 1..1024 bytes")
	}

	recheck, err := w.driver.ReadAuthSnapshot()
	if err != nil {
		return err
	}
	if !sameAuthTarget(stable, recheck) || !recheck.IsAuthDialog {
		return errors.New("authorization target changed before targeted injection")
	}
	if recheck.FocusedValueLength != 0 {
		return errors.New("authorization password field changed before targeted injection")
	}
	if recheck.AuthContextSHA256 != expectedAuthContext {
		return errors.New("authorization dialog context changed before targeted injection")
	}
	if err := w.confirmOsaScriptStillEligible(process, rule); err != nil {
		return fmt.Errorf("final osascript check before targeted injection: %w", err)
	}
	if err := w.driver.InjectUTF8ToPID(stable.PID, secret); err != nil {
		return err
	}
	if !rule.ShouldSubmitAutomatically() {
		w.options.Logger.Printf("typed password for rule=%s; automatic Return disabled", rule.Name)
		return nil
	}
	time.Sleep(50 * time.Millisecond)
	recheck, err = w.driver.ReadAuthSnapshot()
	if err != nil {
		return err
	}
	if !sameAuthTarget(stable, recheck) || !recheck.IsAuthDialog {
		return errors.New("authorization target changed after password injection; Return not sent")
	}
	if recheck.FocusedValueLength != utf16Length(secret) {
		return errors.New("authorization password field length does not match the injected secret; Return not sent")
	}
	if recheck.AuthContextSHA256 != expectedAuthContext {
		return errors.New("authorization dialog context changed after password injection; Return not sent")
	}
	stop, err = w.driver.EmergencyStopHeld(ctx)
	if err != nil || stop {
		return errors.New("Escape emergency stop activated after typing; Return not sent")
	}
	if err := w.confirmOsaScriptStillEligible(process, rule); err != nil {
		return fmt.Errorf("final osascript check before Return: %w", err)
	}
	if err := w.driver.InjectReturnToPID(stable.PID, utf16Length(secret)); err != nil {
		return err
	}
	w.options.Logger.Printf("typed and submitted password for rule=%s osascript_pid=%d auth_pid=%d", rule.Name, process.PID, stable.PID)
	return nil
}

func (w *Watcher) confirmOsaScriptStillEligible(expected darwinbridge.ProcessInfo, rule Rule) error {
	processes, err := w.driver.ListOsaScripts(uint32(os.Getuid()))
	if err != nil {
		return err
	}
	if w.policy.RequiresSingleOsaScriptProcess() && len(processes) != 1 {
		return errors.New("osascript process count changed before password retrieval")
	}
	for _, current := range processes {
		if current.PID != expected.PID || current.StartSeconds != expected.StartSeconds ||
			current.UID != expected.UID || current.ExecutablePath != "/usr/bin/osascript" {
			continue
		}
		if rule.universalRequest &&
			current.ParentPath == expected.ParentPath &&
			current.ParentCodeValid == expected.ParentCodeValid &&
			current.ParentCodeIdentifier == expected.ParentCodeIdentifier &&
			current.ParentCDHash == expected.ParentCDHash &&
			hashArguments(current.Arguments) == hashArguments(expected.Arguments) {
			return nil
		}
		if !rule.universalRequest && current.ParentPath == rule.ParentExecutable && current.ParentCodeValid &&
			current.ParentCodeIdentifier == rule.ParentCodeIdentifier && current.ParentCDHash == rule.ParentCDHash &&
			hashArguments(current.Arguments) == rule.ArgumentsSHA256 {
			return nil
		}
	}
	return errors.New("enrolled osascript process exited or changed before password retrieval")
}

func sameAuthTarget(a, b darwinbridge.AuthSnapshot) bool {
	return eligibleAuthSnapshot(a) && eligibleAuthSnapshot(b) &&
		a.PID == b.PID && a.StartSeconds == b.StartSeconds && a.StartMicroseconds == b.StartMicroseconds &&
		a.CodeIdentifier == b.CodeIdentifier && a.ExecutablePath == b.ExecutablePath &&
		a.FocusedRole == b.FocusedRole && a.FocusedSubrole == b.FocusedSubrole &&
		a.AuthContextComplete && b.AuthContextComplete && a.AuthContextSHA256 == b.AuthContextSHA256 &&
		a.SecureFieldCount == 1 && b.SecureFieldCount == 1
}

func zero(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
	runtime.KeepAlive(secret)
}

func utf16Length(value []byte) int {
	length := 0
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		value = value[size:]
		if r > 0xffff {
			length += 2
		} else {
			length++
		}
	}
	return length
}
