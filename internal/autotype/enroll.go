package autotype

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aiwaki/osaguard/internal/darwinbridge"
)

// EnrollmentDriver is the read-only macOS surface needed to bind a policy rule
// to a newly started osascript and its Apple authorization UI.
type EnrollmentDriver interface {
	ListOsaScripts(uid uint32) ([]darwinbridge.ProcessInfo, error)
	ReadAuthSnapshot() (darwinbridge.AuthSnapshot, error)
}

type EnrollmentOptions struct {
	UID          uint32
	PollInterval time.Duration
	StableChecks int
}

type EnrollmentResult struct {
	Fingerprint Fingerprint
	Snapshot    darwinbridge.AuthSnapshot
}

// WaitForEnrollment waits only for a process that starts after this function's
// initial empty-process check. It never retrieves or types a password.
func WaitForEnrollment(ctx context.Context, driver EnrollmentDriver, options EnrollmentOptions) (EnrollmentResult, error) {
	if driver == nil {
		return EnrollmentResult{}, errors.New("enrollment driver is nil")
	}
	if options.PollInterval < 10*time.Millisecond || options.PollInterval > time.Second {
		return EnrollmentResult{}, errors.New("enrollment poll interval must be between 10ms and 1s")
	}
	if options.StableChecks < 3 || options.StableChecks > 10 {
		return EnrollmentResult{}, errors.New("enrollment stable checks must be between 3 and 10")
	}

	initial, err := driver.ListOsaScripts(options.UID)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("list initial osascript processes: %w", err)
	}
	if len(initial) != 0 {
		return EnrollmentResult{}, fmt.Errorf("close existing osascript processes before enrollment; found %d", len(initial))
	}
	initialAuth, err := driver.ReadAuthSnapshot()
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("read authorization UI at enrollment start: %w", err)
	}
	if !initialAuth.AccessibilityTrusted {
		return EnrollmentResult{}, errors.New("Accessibility permission is not granted")
	}
	observedAuthTargets := make(map[authTargetKey]struct{})
	if key, ok := authTargetIdentity(initialAuth); ok {
		observedAuthTargets[key] = struct{}{}
	}

	ticker := time.NewTicker(options.PollInterval)
	defer ticker.Stop()
	var candidate darwinbridge.ProcessInfo
	var fingerprint Fingerprint
	var stable darwinbridge.AuthSnapshot
	stableCount := 0

	for {
		select {
		case <-ctx.Done():
			return EnrollmentResult{}, fmt.Errorf("wait for a new osascript authorization request: %w", ctx.Err())
		case <-ticker.C:
		}

		processes, err := driver.ListOsaScripts(options.UID)
		if err != nil {
			return EnrollmentResult{}, fmt.Errorf("list osascript processes: %w", err)
		}
		snapshot, err := driver.ReadAuthSnapshot()
		if err != nil {
			return EnrollmentResult{}, fmt.Errorf("read authorization UI: %w", err)
		}
		if !snapshot.AccessibilityTrusted {
			return EnrollmentResult{}, errors.New("Accessibility permission is not granted")
		}
		authTargetWasObserved := false
		if key, ok := authTargetIdentity(snapshot); ok {
			_, authTargetWasObserved = observedAuthTargets[key]
			observedAuthTargets[key] = struct{}{}
		}
		if len(processes) == 0 {
			candidate = darwinbridge.ProcessInfo{}
			fingerprint = Fingerprint{}
			stable = darwinbridge.AuthSnapshot{}
			stableCount = 0
			continue
		}
		if len(processes) != 1 {
			return EnrollmentResult{}, fmt.Errorf("ambiguous enrollment: expected one osascript process, found %d", len(processes))
		}

		process := processes[0]
		processIsNew := candidate.PID != process.PID || candidate.StartSeconds != process.StartSeconds
		if processIsNew && authTargetWasObserved {
			return EnrollmentResult{}, errors.New("authorization target was already visible before this osascript was observed; restart enrollment")
		}
		if processIsNew {
			fingerprint, err = FingerprintProcess(process)
			if err != nil {
				return EnrollmentResult{}, fmt.Errorf("fingerprint new osascript pid %d: %w", process.PID, err)
			}
			candidate = process
			stable = darwinbridge.AuthSnapshot{}
			stableCount = 0
		}

		if !eligibleEnrollmentSnapshot(snapshot) {
			stable = darwinbridge.AuthSnapshot{}
			stableCount = 0
			continue
		}
		if stableCount == 0 || !sameAuthTarget(stable, snapshot) {
			stable = snapshot
			stableCount = 1
		} else {
			stable = snapshot
			stableCount++
		}
		if stableCount < options.StableChecks {
			continue
		}

		finalProcesses, err := driver.ListOsaScripts(options.UID)
		if err != nil {
			return EnrollmentResult{}, fmt.Errorf("final osascript check: %w", err)
		}
		if len(finalProcesses) != 1 || finalProcesses[0].PID != candidate.PID || finalProcesses[0].StartSeconds != candidate.StartSeconds {
			return EnrollmentResult{}, errors.New("osascript process changed during enrollment")
		}
		finalFingerprint, err := FingerprintProcess(finalProcesses[0])
		if err != nil {
			return EnrollmentResult{}, fmt.Errorf("final osascript fingerprint: %w", err)
		}
		if finalFingerprint != fingerprint {
			return EnrollmentResult{}, errors.New("osascript fingerprint changed during enrollment")
		}
		finalSnapshot, err := driver.ReadAuthSnapshot()
		if err != nil {
			return EnrollmentResult{}, fmt.Errorf("final authorization UI check: %w", err)
		}
		if !eligibleEnrollmentSnapshot(finalSnapshot) || !sameAuthTarget(stable, finalSnapshot) {
			return EnrollmentResult{}, errors.New("authorization target changed during final enrollment check")
		}
		return EnrollmentResult{Fingerprint: fingerprint, Snapshot: finalSnapshot}, nil
	}
}

func eligibleEnrollmentSnapshot(snapshot darwinbridge.AuthSnapshot) bool {
	return eligibleAuthSnapshot(snapshot) && snapshot.FocusedValueLength == 0
}
