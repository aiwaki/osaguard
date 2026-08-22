package autotype

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aiwaki/osaguard/internal/darwinbridge"
)

type fakeEnrollmentDriver struct {
	processLists [][]darwinbridge.ProcessInfo
	snapshots    []darwinbridge.AuthSnapshot
}

func (f *fakeEnrollmentDriver) ListOsaScripts(uint32) ([]darwinbridge.ProcessInfo, error) {
	if len(f.processLists) == 0 {
		return nil, nil
	}
	value := f.processLists[0]
	if len(f.processLists) > 1 {
		f.processLists = f.processLists[1:]
	}
	return append([]darwinbridge.ProcessInfo(nil), value...), nil
}

func (f *fakeEnrollmentDriver) ReadAuthSnapshot() (darwinbridge.AuthSnapshot, error) {
	if len(f.snapshots) == 0 {
		return darwinbridge.AuthSnapshot{}, nil
	}
	value := f.snapshots[0]
	if len(f.snapshots) > 1 {
		f.snapshots = f.snapshots[1:]
	}
	return value, nil
}

func enrollmentTestProcess(t *testing.T) darwinbridge.ProcessInfo {
	t.Helper()
	parent, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return darwinbridge.ProcessInfo{
		PID: 41, UID: uint32(os.Getuid()), StartSeconds: 10, ExecutablePath: "/usr/bin/osascript",
		ParentPath: parent, ParentCodeValid: true, ParentCodeIdentifier: "dev.aiwaki.test",
		ParentCDHash: strings.Repeat("d", 40), Arguments: []string{"/usr/bin/osascript", "-e", "return 1"},
	}
}

func enrollmentTestSnapshot(pid int) darwinbridge.AuthSnapshot {
	return darwinbridge.AuthSnapshot{
		AccessibilityTrusted: true, IsAuthDialog: true, PID: pid, StartSeconds: 100, StartMicroseconds: 200,
		AppleSigned: true, AppFrontmost: true, AppOnscreen: true, FocusedEnabled: true,
		CodeIdentifier: "com.apple.SecurityAgent", ExecutablePath: securityAgentPath,
		FocusedRole: "AXTextField", FocusedSubrole: "AXSecureTextField", SecureFieldCount: 1,
		AuthContextComplete: true, AuthContextSHA256: strings.Repeat("c", 64),
	}
}

func TestWaitForEnrollmentCapturesOnlyStableNewRequest(t *testing.T) {
	process := enrollmentTestProcess(t)
	snapshot := enrollmentTestSnapshot(77)
	driver := &fakeEnrollmentDriver{
		processLists: [][]darwinbridge.ProcessInfo{nil, {process}, {process}, {process}, {process}},
		snapshots: []darwinbridge.AuthSnapshot{
			{AccessibilityTrusted: true}, snapshot, snapshot, snapshot, snapshot,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := WaitForEnrollment(ctx, driver, EnrollmentOptions{UID: uint32(os.Getuid()), PollInterval: 10 * time.Millisecond, StableChecks: 3})
	if err != nil {
		t.Fatal(err)
	}
	if result.Fingerprint.PID != process.PID || result.Snapshot.PID != snapshot.PID {
		t.Fatalf("unexpected enrollment result: %+v", result)
	}
}

func TestWaitForEnrollmentRejectsExistingProcess(t *testing.T) {
	process := enrollmentTestProcess(t)
	driver := &fakeEnrollmentDriver{processLists: [][]darwinbridge.ProcessInfo{{process}}}
	_, err := WaitForEnrollment(context.Background(), driver, EnrollmentOptions{UID: uint32(os.Getuid()), PollInterval: 10 * time.Millisecond, StableChecks: 3})
	if err == nil || !strings.Contains(err.Error(), "close existing") {
		t.Fatalf("expected existing-process rejection, got %v", err)
	}
}

func TestWaitForEnrollmentRejectsChangedFinalTarget(t *testing.T) {
	process := enrollmentTestProcess(t)
	snapshot := enrollmentTestSnapshot(77)
	changed := snapshot
	changed.PID = 78
	driver := &fakeEnrollmentDriver{
		processLists: [][]darwinbridge.ProcessInfo{nil, {process}, {process}, {process}, {process}},
		snapshots:    []darwinbridge.AuthSnapshot{{AccessibilityTrusted: true}, snapshot, snapshot, snapshot, changed},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := WaitForEnrollment(ctx, driver, EnrollmentOptions{UID: uint32(os.Getuid()), PollInterval: 10 * time.Millisecond, StableChecks: 3})
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("expected changed-target rejection, got %v", err)
	}
}

func TestWaitForEnrollmentRejectsChangedFinalProcessIdentity(t *testing.T) {
	process := enrollmentTestProcess(t)
	changed := process
	changed.ParentCDHash = strings.Repeat("e", 40)
	snapshot := enrollmentTestSnapshot(77)
	driver := &fakeEnrollmentDriver{
		processLists: [][]darwinbridge.ProcessInfo{nil, {process}, {process}, {process}, {changed}},
		snapshots:    []darwinbridge.AuthSnapshot{{AccessibilityTrusted: true}, snapshot, snapshot, snapshot},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := WaitForEnrollment(ctx, driver, EnrollmentOptions{UID: uint32(os.Getuid()), PollInterval: 10 * time.Millisecond, StableChecks: 3})
	if err == nil || !strings.Contains(err.Error(), "fingerprint changed") {
		t.Fatalf("expected changed-process rejection, got %v", err)
	}
}

func TestWaitForEnrollmentRejectsPreexistingAuthorizationTarget(t *testing.T) {
	process := enrollmentTestProcess(t)
	snapshot := enrollmentTestSnapshot(77)
	driver := &fakeEnrollmentDriver{
		processLists: [][]darwinbridge.ProcessInfo{nil, {process}},
		snapshots:    []darwinbridge.AuthSnapshot{snapshot, snapshot},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := WaitForEnrollment(ctx, driver, EnrollmentOptions{UID: uint32(os.Getuid()), PollInterval: 10 * time.Millisecond, StableChecks: 3})
	if err == nil || !strings.Contains(err.Error(), "already visible") {
		t.Fatalf("expected pre-existing authorization target rejection, got %v", err)
	}
}

func TestEligibleEnrollmentSnapshotRequiresQualifiedFrontmostSecurityAgent(t *testing.T) {
	base := enrollmentTestSnapshot(77)
	for name, mutate := range map[string]func(*darwinbridge.AuthSnapshot){
		"authorizationhost": func(snapshot *darwinbridge.AuthSnapshot) {
			snapshot.CodeIdentifier = "com.apple.authorizationhost"
		},
		"offscreen": func(snapshot *darwinbridge.AuthSnapshot) { snapshot.AppOnscreen = false },
		"disabled":  func(snapshot *darwinbridge.AuthSnapshot) { snapshot.FocusedEnabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := base
			mutate(&snapshot)
			if eligibleEnrollmentSnapshot(snapshot) {
				t.Fatal("unqualified authorization snapshot unexpectedly accepted for enrollment")
			}
		})
	}
}
