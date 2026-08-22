package autotype

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/aiwaki/osaguard/internal/darwinbridge"
)

type fakeDriver struct {
	snapshots      []darwinbridge.AuthSnapshot
	snapshotErrors []error
	processes      []darwinbridge.ProcessInfo
	secret         []byte
	loadCount      int
	typedPID       int
	typedText      string
	returnPID      int
}

func (f *fakeDriver) ListOsaScripts(uint32) ([]darwinbridge.ProcessInfo, error) {
	return append([]darwinbridge.ProcessInfo(nil), f.processes...), nil
}
func (f *fakeDriver) SessionUnlocked() bool { return true }
func (f *fakeDriver) ReadAuthSnapshot() (darwinbridge.AuthSnapshot, error) {
	if len(f.snapshotErrors) > 0 {
		err := f.snapshotErrors[0]
		f.snapshotErrors = f.snapshotErrors[1:]
		if err != nil {
			return darwinbridge.AuthSnapshot{}, err
		}
	}
	if len(f.snapshots) == 0 {
		return darwinbridge.AuthSnapshot{}, nil
	}
	value := f.snapshots[0]
	f.snapshots = f.snapshots[1:]
	if f.typedText != "" {
		value.FocusedValueLength = len(f.typedText)
	}
	return value, nil
}
func (f *fakeDriver) KeychainLoad(string) ([]byte, error) {
	f.loadCount++
	return append([]byte(nil), f.secret...), nil
}
func (f *fakeDriver) InjectUTF8ToPID(pid int, secret []byte) error {
	f.typedPID, f.typedText = pid, string(secret)
	return nil
}
func (f *fakeDriver) InjectReturnToPID(pid int, expectedLength int) error {
	if expectedLength != len(f.typedText) {
		return errors.New("unexpected secure-field length")
	}
	f.returnPID = pid
	return nil
}
func (f *fakeDriver) EmergencyStopHeld(context.Context) (bool, error) { return false, nil }

func secureAuthSnapshot(pid int, digestByte string) darwinbridge.AuthSnapshot {
	return darwinbridge.AuthSnapshot{
		AccessibilityTrusted: true, IsAuthDialog: true, PID: pid,
		StartSeconds: 100, StartMicroseconds: 200, AppleSigned: true, AppFrontmost: true,
		AppOnscreen: true, FocusedEnabled: true,
		CodeIdentifier: "com.apple.SecurityAgent", ExecutablePath: securityAgentPath,
		FocusedRole: "AXTextField", FocusedSubrole: "AXSecureTextField", SecureFieldCount: 1,
		AuthContextComplete: true, AuthContextSHA256: strings.Repeat(digestByte, 64),
	}
}

func TestSameAuthTarget(t *testing.T) {
	base := secureAuthSnapshot(42, "c")
	if !sameAuthTarget(base, base) {
		t.Fatal("identical secure targets should match")
	}
	changed := base
	changed.PID++
	if sameAuthTarget(base, changed) {
		t.Fatal("different pids must not match")
	}
	changed = base
	changed.SecureFieldCount = 2
	if sameAuthTarget(base, changed) {
		t.Fatal("multiple secure fields must not match")
	}
	changed = base
	changed.StartMicroseconds++
	if sameAuthTarget(base, changed) {
		t.Fatal("reused pid with a changed process generation must not match")
	}
}

func TestUnsupportedOrBackgroundAuthorizationUIFailsBeforeKeychainLoad(t *testing.T) {
	process := darwinbridge.ProcessInfo{PID: 9, UID: uint32(os.Getuid()), StartSeconds: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/usr/bin/true", Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	policy := NewUniversalPolicy("alice")
	rule, err := policy.Match(process)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*darwinbridge.AuthSnapshot){
		"authorizationhost": func(snapshot *darwinbridge.AuthSnapshot) {
			snapshot.CodeIdentifier = "com.apple.authorizationhost"
			snapshot.ExecutablePath = "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/authorizationhost.bundle/Contents/MacOS/authorizationhost"
		},
		"coreautha": func(snapshot *darwinbridge.AuthSnapshot) {
			snapshot.CodeIdentifier = "com.apple.LocalAuthentication.UIAgent"
			snapshot.ExecutablePath = "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreautha.bundle/Contents/MacOS/coreautha"
		},
		"background SecurityAgent": func(snapshot *darwinbridge.AuthSnapshot) { snapshot.AppFrontmost = false },
		"offscreen SecurityAgent":  func(snapshot *darwinbridge.AuthSnapshot) { snapshot.AppOnscreen = false },
		"disabled secure field":    func(snapshot *darwinbridge.AuthSnapshot) { snapshot.FocusedEnabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := secureAuthSnapshot(77, "c")
			mutate(&snapshot)
			driver := &fakeDriver{snapshots: []darwinbridge.AuthSnapshot{snapshot}, processes: []darwinbridge.ProcessInfo{process}, secret: []byte("secret")}
			watcher, err := NewWatcher(policy, WatchOptions{driver: driver, Logger: log.New(&bytes.Buffer{}, "", 0)})
			if err != nil {
				t.Fatal(err)
			}
			if err := watcher.confirmAndType(context.Background(), process, *rule); err == nil {
				t.Fatal("unsupported authorization UI unexpectedly accepted")
			}
			if driver.loadCount != 0 || driver.typedText != "" {
				t.Fatalf("unsupported UI reached secret handling: %+v", driver)
			}
		})
	}
}

func TestPreexistingAuthorizationTargetRejectsNewOsaScriptPermanently(t *testing.T) {
	process := darwinbridge.ProcessInfo{PID: 9, UID: uint32(os.Getuid()), StartSeconds: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/usr/bin/true", Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	snapshot := secureAuthSnapshot(77, "c")
	driver := &fakeDriver{snapshots: []darwinbridge.AuthSnapshot{snapshot, snapshot, darwinbridge.AuthSnapshot{}}, secret: []byte("secret")}
	watcher, err := NewWatcher(NewUniversalPolicy("alice"), WatchOptions{driver: driver, Logger: log.New(&bytes.Buffer{}, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	driver.processes = []darwinbridge.ProcessInfo{process}
	if err := watcher.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if observed := watcher.observed[process.PID]; observed == nil || !observed.handled {
		t.Fatal("new osascript was not permanently rejected against a pre-existing auth target")
	}
	if err := watcher.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if driver.loadCount != 0 || driver.typedText != "" {
		t.Fatalf("pre-existing target reached secret handling: %+v", driver)
	}
}

func TestAuthInspectionErrorPermanentlyRejectsNewlyObservedOsaScript(t *testing.T) {
	process := darwinbridge.ProcessInfo{PID: 9, UID: uint32(os.Getuid()), StartSeconds: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/usr/bin/true", Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	driver := &fakeDriver{
		processes:      []darwinbridge.ProcessInfo{process},
		snapshotErrors: []error{errors.New("unsupported or ambiguous Apple authorization UI is visible")},
		snapshots:      []darwinbridge.AuthSnapshot{secureAuthSnapshot(77, "c")},
		secret:         []byte("secret"),
	}
	watcher, err := NewWatcher(NewUniversalPolicy("alice"), WatchOptions{driver: driver, Logger: log.New(&bytes.Buffer{}, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.poll(context.Background()); err == nil {
		t.Fatal("ambiguous authorization UI error unexpectedly ignored")
	}
	if observed := watcher.observed[process.PID]; observed == nil || !observed.handled {
		t.Fatal("osascript first seen during ambiguous UI was not permanently rejected")
	}
	if err := watcher.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if driver.loadCount != 0 || driver.typedText != "" {
		t.Fatalf("rejected osascript was later paired after conflict cleared: %+v", driver)
	}
}

func TestZero(t *testing.T) {
	secret := []byte("sensitive")
	zero(secret)
	for _, value := range secret {
		if value != 0 {
			t.Fatal("secret was not zeroed")
		}
	}
}

func TestUTF16Length(t *testing.T) {
	if got := utf16Length([]byte("a😀б")); got != 4 {
		t.Fatalf("got %d", got)
	}
}

func TestConfirmAndTypeTargetsOnlyStableAuthPID(t *testing.T) {
	snapshot := secureAuthSnapshot(77, "c")
	process := darwinbridge.ProcessInfo{PID: 9, UID: 0, StartSeconds: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/usr/bin/true", ParentCodeValid: true, ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40), Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	rule := Rule{Name: "test", ArgumentsSHA256: hashArguments(process.Arguments), ParentExecutable: "/usr/bin/true", ParentSHA256: strings.Repeat("b", 64), ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40), AuthContextSHA256: strings.Repeat("c", 64)}
	driver := &fakeDriver{snapshots: []darwinbridge.AuthSnapshot{snapshot, snapshot, snapshot, snapshot, snapshot}, processes: []darwinbridge.ProcessInfo{process}, secret: []byte("secret")}
	policy := &Policy{Version: 1, Account: "alice", PollMilliseconds: 50, StableChecks: 3, Rules: []Rule{rule}}
	watcher, err := NewWatcher(policy, WatchOptions{driver: driver, Logger: log.New(&bytes.Buffer{}, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.confirmAndType(context.Background(), process, policy.Rules[0]); err != nil {
		t.Fatal(err)
	}
	if driver.typedPID != 77 || driver.returnPID != 77 || driver.typedText != "secret" {
		t.Fatalf("unexpected targeted events: %+v", driver)
	}
}

func TestConfirmAndTypeRejectsChangedAuthPID(t *testing.T) {
	base := secureAuthSnapshot(77, "c")
	changed := base
	changed.PID = 78
	process := darwinbridge.ProcessInfo{PID: 9, UID: 0, StartSeconds: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/usr/bin/true", ParentCodeValid: true, ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40), Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	rule := Rule{Name: "test", ArgumentsSHA256: hashArguments(process.Arguments), ParentExecutable: "/usr/bin/true", ParentSHA256: strings.Repeat("b", 64), ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40), AuthContextSHA256: strings.Repeat("c", 64)}
	driver := &fakeDriver{snapshots: []darwinbridge.AuthSnapshot{base, changed}, processes: []darwinbridge.ProcessInfo{process}, secret: []byte("secret")}
	policy := &Policy{Version: 1, Account: "alice", PollMilliseconds: 50, StableChecks: 3, Rules: []Rule{rule}}
	watcher, err := NewWatcher(policy, WatchOptions{driver: driver, Logger: log.New(&bytes.Buffer{}, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	err = watcher.confirmAndType(context.Background(), process, policy.Rules[0])
	if err == nil || driver.typedText != "" {
		t.Fatalf("changed target must fail before typing; err=%v", err)
	}
}

func TestUniversalConfirmLearnsAndStabilizesOperationAuthContext(t *testing.T) {
	snapshot := secureAuthSnapshot(77, "c")
	process := darwinbridge.ProcessInfo{PID: 9, UID: uint32(os.Getuid()), StartSeconds: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/Users/alice/bin/unsigned", ParentCodeValid: false, Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	policy := NewUniversalPolicy("alice")
	policy.PollMilliseconds = 50
	policy.StableChecks = 3
	rule, err := policy.Match(process)
	if err != nil {
		t.Fatal(err)
	}
	driver := &fakeDriver{snapshots: []darwinbridge.AuthSnapshot{snapshot, snapshot, snapshot, snapshot, snapshot}, processes: []darwinbridge.ProcessInfo{process}, secret: []byte("secret")}
	watcher, err := NewWatcher(policy, WatchOptions{driver: driver, Logger: log.New(&bytes.Buffer{}, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.confirmAndType(context.Background(), process, *rule); err != nil {
		t.Fatal(err)
	}
	if driver.typedPID != 77 || driver.returnPID != 77 || driver.typedText != "secret" {
		t.Fatalf("universal request was not targeted correctly: %+v", driver)
	}
}

func TestUniversalConfirmRejectsAuthContextChangeBeforeSecretRetrieval(t *testing.T) {
	base := secureAuthSnapshot(77, "c")
	changed := base
	changed.AuthContextSHA256 = strings.Repeat("d", 64)
	process := darwinbridge.ProcessInfo{PID: 9, UID: uint32(os.Getuid()), StartSeconds: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/Users/alice/bin/unsigned", Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	policy := NewUniversalPolicy("alice")
	policy.PollMilliseconds = 50
	policy.StableChecks = 3
	rule, err := policy.Match(process)
	if err != nil {
		t.Fatal(err)
	}
	driver := &fakeDriver{snapshots: []darwinbridge.AuthSnapshot{base, changed}, processes: []darwinbridge.ProcessInfo{process}, secret: []byte("secret")}
	watcher, err := NewWatcher(policy, WatchOptions{driver: driver, Logger: log.New(&bytes.Buffer{}, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	err = watcher.confirmAndType(context.Background(), process, *rule)
	if err == nil || !strings.Contains(err.Error(), "context changed") || driver.typedText != "" {
		t.Fatalf("changed operation context must fail before typing; err=%v driver=%+v", err, driver)
	}
}

func TestExactConfirmStillRequiresEnrolledAuthContext(t *testing.T) {
	snapshot := secureAuthSnapshot(77, "d")
	process := darwinbridge.ProcessInfo{PID: 9, UID: 0, StartSeconds: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/usr/bin/true", ParentCodeValid: true, ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40), Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	rule := Rule{Name: "test", ArgumentsSHA256: hashArguments(process.Arguments), ParentExecutable: "/usr/bin/true", ParentSHA256: strings.Repeat("b", 64), ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40), AuthContextSHA256: strings.Repeat("c", 64)}
	driver := &fakeDriver{snapshots: []darwinbridge.AuthSnapshot{snapshot}, processes: []darwinbridge.ProcessInfo{process}, secret: []byte("secret")}
	policy := &Policy{Version: 1, Account: "alice", PollMilliseconds: 50, StableChecks: 3, Rules: []Rule{rule}}
	watcher, err := NewWatcher(policy, WatchOptions{driver: driver, Logger: log.New(&bytes.Buffer{}, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	err = watcher.confirmAndType(context.Background(), process, rule)
	if err == nil || !strings.Contains(err.Error(), "enrolled rule") || driver.typedText != "" {
		t.Fatalf("exact mode auth-context binding regressed; err=%v driver=%+v", err, driver)
	}
}

func TestUniversalEligibilityRequiresSameOperationProcess(t *testing.T) {
	expected := darwinbridge.ProcessInfo{PID: 9, UID: uint32(os.Getuid()), StartSeconds: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/Users/alice/bin/unsigned", Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	current := expected
	current.Arguments = []string{"/usr/bin/osascript", "-e", "return 2"}
	policy := NewUniversalPolicy("alice")
	rule, err := policy.Match(expected)
	if err != nil {
		t.Fatal(err)
	}
	watcher, err := NewWatcher(policy, WatchOptions{driver: &fakeDriver{processes: []darwinbridge.ProcessInfo{current}}, Logger: log.New(&bytes.Buffer{}, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.confirmOsaScriptStillEligible(expected, *rule); err == nil {
		t.Fatal("universal mode must reject a changed operation before password retrieval")
	}
}

func TestUniversalRunLogsPasswordlessAdminWarning(t *testing.T) {
	var logs bytes.Buffer
	policy := NewUniversalPolicy("alice")
	watcher, err := NewWatcher(policy, WatchOptions{DryRun: true, driver: &fakeDriver{}, Logger: log.New(&logs, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := watcher.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected watcher result: %v", err)
	}
	if !strings.Contains(logs.String(), "UNIVERSAL MODE") || !strings.Contains(logs.String(), "passwordless administrator") {
		t.Fatalf("universal risk warning missing: %q", logs.String())
	}
}

func TestConfirmOsaScriptRejectsChangedRuntimeParentIdentity(t *testing.T) {
	process := darwinbridge.ProcessInfo{PID: 9, UID: 0, StartSeconds: 1, ExecutablePath: "/usr/bin/osascript", ParentPath: "/usr/bin/true", ParentCodeValid: true, ParentCodeIdentifier: "com.example.changed", ParentCDHash: strings.Repeat("e", 40), Arguments: []string{"/usr/bin/osascript", "-e", "return 1"}}
	rule := Rule{Name: "test", ArgumentsSHA256: hashArguments(process.Arguments), ParentExecutable: "/usr/bin/true", ParentSHA256: strings.Repeat("b", 64), ParentCodeIdentifier: "com.apple.true", ParentCDHash: strings.Repeat("d", 40), AuthContextSHA256: strings.Repeat("c", 64)}
	policy := &Policy{Version: 1, Account: "alice", Rules: []Rule{rule}}
	watcher, err := NewWatcher(policy, WatchOptions{driver: &fakeDriver{processes: []darwinbridge.ProcessInfo{process}}, Logger: log.New(&bytes.Buffer{}, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.confirmOsaScriptStillEligible(process, rule); err == nil {
		t.Fatal("changed running parent code identity must fail closed")
	}
}
