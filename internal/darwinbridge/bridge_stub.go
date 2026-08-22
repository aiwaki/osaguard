//go:build !darwin || !cgo

package darwinbridge

import "errors"

var ErrPasswordPromptCanceled = errors.New("password entry canceled")
var ErrKeychainItemNeedsReenrollment = errors.New("keychain item belongs to a different application identity")
var ErrKeychainInteractionNotAllowed = errors.New("keychain operation requires forbidden user interaction")

type KeychainItemState string

const (
	KeychainItemMissing           KeychainItemState = "missing"
	KeychainItemReady             KeychainItemState = "ready"
	KeychainItemNeedsReenrollment KeychainItemState = "needs_reenrollment"
)

type IntegrityState string

const (
	IntegrityStatePaused  IntegrityState = "acknowledged_paused"
	IntegrityStateEnabled IntegrityState = "acknowledged_enabled"
)

type AuthSnapshot struct {
	AccessibilityTrusted bool
	PID                  int
	StartSeconds         int64
	StartMicroseconds    int64
	AppleSigned          bool
	AppFrontmost         bool
	AppOnscreen          bool
	FocusedEnabled       bool
	FocusedValueLength   int
	SecureFieldCount     int
	IsAuthDialog         bool
	CodeIdentifier       string
	ExecutablePath       string
	FocusedRole          string
	FocusedSubrole       string
	WindowTitle          string
	AuthContextSHA256    string
	AuthContextComplete  bool
}

type ProcessInfo struct {
	PID                  int
	PPID                 int
	UID                  uint32
	StartSeconds         int64
	ExecutablePath       string
	ParentPath           string
	ParentCodeValid      bool
	ParentCodeIdentifier string
	ParentCDHash         string
	Arguments            []string
}

func ReadAuthSnapshot() (AuthSnapshot, error)          { return AuthSnapshot{}, unsupported() }
func KeychainStore(string, []byte) error               { return unsupported() }
func KeychainLoad(string) ([]byte, error)              { return nil, unsupported() }
func KeychainStatus(string) (KeychainItemState, error) { return "", unsupported() }
func KeychainExists(string) (bool, error)              { return false, unsupported() }
func KeychainDelete(string) error                      { return unsupported() }
func KeychainDeleteAll() error                         { return unsupported() }
func IntegrityStateStore(IntegrityState) error         { return unsupported() }
func IntegrityStateLoad() (IntegrityState, bool, error) {
	return "", false, unsupported()
}
func IntegrityStateStatus() (IntegrityState, KeychainItemState, error) {
	return "", "", unsupported()
}
func IntegrityStateDelete() error { return unsupported() }
func IntegrityStateACLTrustsPathForTesting(string) (bool, error) {
	return false, unsupported()
}
func InjectTextToPID(int, string) error     { return unsupported() }
func InjectUTF8ToPID(int, []byte) error     { return unsupported() }
func InjectReturnToPID(int, int) error      { return unsupported() }
func SessionUnlocked() bool                 { return false }
func AccessibilityTrusted() bool            { return false }
func RequestAccessibility() (bool, error)   { return false, unsupported() }
func PromptPassword(string) ([]byte, error) { return nil, unsupported() }
func ListOsaScripts(uint32) ([]ProcessInfo, error) {
	return nil, unsupported()
}

func unsupported() error { return errors.New("macOS with cgo is required") }
