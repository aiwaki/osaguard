//go:build darwin && cgo

package darwinbridge

/*
#cgo LDFLAGS: -framework AppKit -framework ApplicationServices -framework Security -framework CoreFoundation
#include <stdlib.h>

typedef struct {
    int accessibility_trusted;
    int pid;
    long long start_seconds;
    long long start_microseconds;
    int apple_signed;
    int app_frontmost;
    int app_onscreen;
    int focused_enabled;
    int focused_value_length;
    int secure_field_count;
    int is_auth_dialog;
    int auth_context_complete;
    int unsupported_auth_ui;
    char code_identifier[128];
    char executable_path[1024];
    char focused_role[128];
    char focused_subrole[128];
    char window_title[512];
    char auth_context[4096];
} og_auth_snapshot;

typedef struct {
    int pid;
    int ppid;
    unsigned int uid;
    long long start_seconds;
    int parent_code_valid;
    char executable_path[1024];
    char parent_path[1024];
    char parent_code_identifier[128];
    char parent_cdhash[128];
} og_process_info;

int og_read_auth_snapshot(og_auth_snapshot *out, char *err, size_t err_len);
int og_keychain_store(const char *account, const unsigned char *secret, size_t secret_len, char *err, size_t err_len);
int og_keychain_load(const char *account, unsigned char **secret, size_t *secret_len, char *err, size_t err_len);
int og_keychain_exists(const char *account, char *err, size_t err_len);
int og_keychain_delete(const char *account, char *err, size_t err_len);
int og_keychain_delete_all(char *err, size_t err_len);
int og_integrity_state_store(const unsigned char *state, size_t state_len, char *err, size_t err_len);
int og_integrity_state_load(unsigned char **state, size_t *state_len, char *err, size_t err_len);
int og_integrity_state_delete(char *err, size_t err_len);
int og_integrity_state_acl_trusts_path_for_testing(const char *path, char *err, size_t err_len);
int og_list_osascript(unsigned int uid, og_process_info *out, int capacity, char *err, size_t err_len);
int og_copy_process_args(int pid, unsigned char **data, size_t *data_len, char *err, size_t err_len);
int og_inject_text_to_pid(int pid, const unsigned short *units, size_t unit_count, char *err, size_t err_len);
int og_inject_return_to_pid(int pid, int expected_length, char *err, size_t err_len);
int og_session_unlocked(void);
int og_accessibility_trusted(void);
int og_request_accessibility(void);
int og_prompt_password(const char *locale, unsigned char **secret, size_t *secret_len, char *err, size_t err_len);
void og_free(void *ptr);
void og_secure_free(void *ptr, size_t len);
*/
import "C"

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

const maxOsaScriptProcesses = 64

var ErrPasswordPromptCanceled = errors.New("password entry canceled")
var ErrKeychainItemNeedsReenrollment = errors.New("keychain item belongs to a different application identity")

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

func ReadAuthSnapshot() (AuthSnapshot, error) {
	var raw C.og_auth_snapshot
	var errBuf [512]C.char
	if C.og_read_auth_snapshot(&raw, &errBuf[0], C.size_t(len(errBuf))) != 0 {
		return AuthSnapshot{}, bridgeError(errBuf[:])
	}
	contextText := C.GoString(&raw.auth_context[0])
	contextDigest := ""
	if contextText != "" {
		sum := sha256.Sum256([]byte(contextText))
		contextDigest = hex.EncodeToString(sum[:])
	}
	return AuthSnapshot{
		AccessibilityTrusted: raw.accessibility_trusted != 0,
		PID:                  int(raw.pid),
		StartSeconds:         int64(raw.start_seconds),
		StartMicroseconds:    int64(raw.start_microseconds),
		AppleSigned:          raw.apple_signed != 0,
		AppFrontmost:         raw.app_frontmost != 0,
		AppOnscreen:          raw.app_onscreen != 0,
		FocusedEnabled:       raw.focused_enabled != 0,
		FocusedValueLength:   int(raw.focused_value_length),
		SecureFieldCount:     int(raw.secure_field_count),
		IsAuthDialog:         raw.is_auth_dialog != 0,
		CodeIdentifier:       C.GoString(&raw.code_identifier[0]),
		ExecutablePath:       C.GoString(&raw.executable_path[0]),
		FocusedRole:          C.GoString(&raw.focused_role[0]),
		FocusedSubrole:       C.GoString(&raw.focused_subrole[0]),
		WindowTitle:          C.GoString(&raw.window_title[0]),
		AuthContextSHA256:    contextDigest,
		AuthContextComplete:  raw.auth_context_complete != 0,
	}, nil
}

func KeychainStore(account string, secret []byte) error {
	if account == "" || len(secret) == 0 {
		return errors.New("account and secret must not be empty")
	}
	accountC := C.CString(account)
	defer C.free(unsafe.Pointer(accountC))
	var errBuf [512]C.char
	if C.og_keychain_store(
		accountC,
		(*C.uchar)(unsafe.Pointer(&secret[0])),
		C.size_t(len(secret)),
		&errBuf[0],
		C.size_t(len(errBuf)),
	) != 0 {
		return bridgeError(errBuf[:])
	}
	return nil
}

func KeychainLoad(account string) ([]byte, error) {
	if account == "" {
		return nil, errors.New("account must not be empty")
	}
	accountC := C.CString(account)
	defer C.free(unsafe.Pointer(accountC))
	var secret *C.uchar
	var secretLen C.size_t
	var errBuf [512]C.char
	if C.og_keychain_load(accountC, &secret, &secretLen, &errBuf[0], C.size_t(len(errBuf))) != 0 {
		return nil, bridgeError(errBuf[:])
	}
	if secret == nil || secretLen == 0 || secretLen > 4096 {
		if secret != nil {
			C.og_free(unsafe.Pointer(secret))
		}
		return nil, errors.New("keychain returned an invalid secret length")
	}
	defer C.og_secure_free(unsafe.Pointer(secret), secretLen)
	return C.GoBytes(unsafe.Pointer(secret), C.int(secretLen)), nil
}

func decodeKeychainItemState(result int32) (KeychainItemState, bool) {
	switch result {
	case 0:
		return KeychainItemMissing, true
	case 1:
		return KeychainItemReady, true
	case 2:
		return KeychainItemNeedsReenrollment, true
	default:
		return "", false
	}
}

func KeychainStatus(account string) (KeychainItemState, error) {
	if account == "" {
		return "", errors.New("account must not be empty")
	}
	accountC := C.CString(account)
	defer C.free(unsafe.Pointer(accountC))
	var errBuf [512]C.char
	result := C.og_keychain_exists(accountC, &errBuf[0], C.size_t(len(errBuf)))
	if state, ok := decodeKeychainItemState(int32(result)); ok {
		return state, nil
	}
	return "", bridgeError(errBuf[:])
}

func KeychainExists(account string) (bool, error) {
	state, err := KeychainStatus(account)
	if err != nil {
		return false, err
	}
	if state == KeychainItemNeedsReenrollment {
		return false, ErrKeychainItemNeedsReenrollment
	}
	return state == KeychainItemReady, nil
}

func KeychainDelete(account string) error {
	if account == "" {
		return errors.New("account must not be empty")
	}
	accountC := C.CString(account)
	defer C.free(unsafe.Pointer(accountC))
	var errBuf [512]C.char
	if C.og_keychain_delete(accountC, &errBuf[0], C.size_t(len(errBuf))) != 0 {
		return bridgeError(errBuf[:])
	}
	return nil
}

// KeychainDeleteAll removes every generic-password item in OsaGuard's dedicated
// password service that has OsaGuard's caller-only ACL. It deliberately does
// not change the user's Keychain search list or default Keychain. An ambiguous
// or poisoned same-service item makes removal fail before any verified item is
// deleted, rather than claiming that every saved password was removed.
func KeychainDeleteAll() error {
	var errBuf [512]C.char
	if C.og_keychain_delete_all(&errBuf[0], C.size_t(len(errBuf))) != 0 {
		return bridgeError(errBuf[:])
	}
	return nil
}

func IntegrityStateStore(state IntegrityState) error {
	if state != IntegrityStatePaused && state != IntegrityStateEnabled {
		return errors.New("invalid protected product state")
	}
	value := []byte(state)
	defer zeroBytes(value)
	var errBuf [512]C.char
	if C.og_integrity_state_store(
		(*C.uchar)(unsafe.Pointer(&value[0])),
		C.size_t(len(value)),
		&errBuf[0],
		C.size_t(len(errBuf)),
	) != 0 {
		return bridgeError(errBuf[:])
	}
	return nil
}

func IntegrityStateStatus() (IntegrityState, KeychainItemState, error) {
	var value *C.uchar
	var valueLen C.size_t
	var errBuf [512]C.char
	result := C.og_integrity_state_load(&value, &valueLen, &errBuf[0], C.size_t(len(errBuf)))
	if result == 0 {
		return "", KeychainItemMissing, nil
	}
	if result == 2 {
		return "", KeychainItemNeedsReenrollment, nil
	}
	if result != 1 {
		return "", "", bridgeError(errBuf[:])
	}
	if value == nil || valueLen == 0 || valueLen > 64 {
		if value != nil {
			C.og_secure_free(unsafe.Pointer(value), valueLen)
		}
		return "", "", errors.New("protected product state has invalid length")
	}
	defer C.og_secure_free(unsafe.Pointer(value), valueLen)
	state := IntegrityState(C.GoStringN((*C.char)(unsafe.Pointer(value)), C.int(valueLen)))
	if state != IntegrityStatePaused && state != IntegrityStateEnabled {
		return "", "", errors.New("protected product state has invalid value")
	}
	return state, KeychainItemReady, nil
}

func IntegrityStateLoad() (IntegrityState, bool, error) {
	state, itemState, err := IntegrityStateStatus()
	if err != nil {
		return "", false, err
	}
	if itemState == KeychainItemNeedsReenrollment {
		return "", false, ErrKeychainItemNeedsReenrollment
	}
	return state, itemState == KeychainItemReady, nil
}

func IntegrityStateDelete() error {
	var errBuf [512]C.char
	if C.og_integrity_state_delete(&errBuf[0], C.size_t(len(errBuf))) != 0 {
		return bridgeError(errBuf[:])
	}
	return nil
}

func IntegrityStateACLTrustsPathForTesting(path string) (bool, error) {
	if path == "" {
		return false, errors.New("trusted application path must not be empty")
	}
	pathC := C.CString(path)
	defer C.free(unsafe.Pointer(pathC))
	var errBuf [512]C.char
	result := C.og_integrity_state_acl_trusts_path_for_testing(pathC, &errBuf[0], C.size_t(len(errBuf)))
	if result < 0 {
		return false, bridgeError(errBuf[:])
	}
	return result == 1, nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
	runtime.KeepAlive(value)
}

func InjectTextToPID(pid int, text string) error {
	if pid <= 0 || text == "" {
		return errors.New("target pid and text must be set")
	}
	units := utf16.Encode([]rune(text))
	if len(units) > 4096 {
		return errors.New("text exceeds 4096 UTF-16 units")
	}
	var errBuf [512]C.char
	if C.og_inject_text_to_pid(
		C.int(pid),
		(*C.ushort)(unsafe.Pointer(&units[0])),
		C.size_t(len(units)),
		&errBuf[0],
		C.size_t(len(errBuf)),
	) != 0 {
		return bridgeError(errBuf[:])
	}
	return nil
}

func InjectUTF8ToPID(pid int, secret []byte) error {
	if pid <= 0 || len(secret) == 0 || !utf8.Valid(secret) {
		return errors.New("target pid and valid UTF-8 secret must be set")
	}
	units := make([]uint16, 0, len(secret))
	for len(secret) > 0 {
		r, size := utf8.DecodeRune(secret)
		secret = secret[size:]
		if r <= 0xffff {
			units = append(units, uint16(r))
		} else {
			high, low := utf16.EncodeRune(r)
			units = append(units, uint16(high), uint16(low))
		}
	}
	if len(units) > 4096 {
		zeroUTF16(units)
		return errors.New("secret exceeds 4096 UTF-16 units")
	}
	defer zeroUTF16(units)
	var errBuf [512]C.char
	if C.og_inject_text_to_pid(
		C.int(pid),
		(*C.ushort)(unsafe.Pointer(&units[0])),
		C.size_t(len(units)),
		&errBuf[0],
		C.size_t(len(errBuf)),
	) != 0 {
		return bridgeError(errBuf[:])
	}
	return nil
}

func zeroUTF16(units []uint16) {
	for i := range units {
		units[i] = 0
	}
	runtime.KeepAlive(units)
}

func InjectReturnToPID(pid int, expectedLength int) error {
	if pid <= 0 || expectedLength <= 0 {
		return errors.New("target pid and expected secure-field length must be set")
	}
	var errBuf [512]C.char
	if C.og_inject_return_to_pid(C.int(pid), C.int(expectedLength), &errBuf[0], C.size_t(len(errBuf))) != 0 {
		return bridgeError(errBuf[:])
	}
	return nil
}

func SessionUnlocked() bool {
	return C.og_session_unlocked() != 0
}

func AccessibilityTrusted() bool {
	return C.og_accessibility_trusted() != 0
}

func RequestAccessibility() (bool, error) {
	return C.og_request_accessibility() != 0, nil
}

func PromptPassword(locale string) ([]byte, error) {
	if locale != "system" && locale != "ru" && locale != "en" {
		return nil, errors.New("locale must be system, ru, or en")
	}
	localeC := C.CString(locale)
	defer C.free(unsafe.Pointer(localeC))
	var secret *C.uchar
	var secretLen C.size_t
	var errBuf [512]C.char
	result := C.og_prompt_password(localeC, &secret, &secretLen, &errBuf[0], C.size_t(len(errBuf)))
	if result == 1 {
		return nil, ErrPasswordPromptCanceled
	}
	if result != 0 {
		return nil, bridgeError(errBuf[:])
	}
	if secret == nil || secretLen == 0 || secretLen > 1024 {
		if secret != nil {
			C.og_secure_free(unsafe.Pointer(secret), secretLen)
		}
		return nil, errors.New("password dialog returned an invalid secret length")
	}
	defer C.og_secure_free(unsafe.Pointer(secret), secretLen)
	return C.GoBytes(unsafe.Pointer(secret), C.int(secretLen)), nil
}

func ListOsaScripts(uid uint32) ([]ProcessInfo, error) {
	raw := make([]C.og_process_info, maxOsaScriptProcesses)
	var errBuf [512]C.char
	count := C.og_list_osascript(
		C.uint(uid),
		&raw[0],
		C.int(len(raw)),
		&errBuf[0],
		C.size_t(len(errBuf)),
	)
	if count < 0 {
		return nil, bridgeError(errBuf[:])
	}
	if int(count) > len(raw) {
		return nil, fmt.Errorf("more than %d osascript processes are active", len(raw))
	}
	result := make([]ProcessInfo, 0, int(count))
	for i := 0; i < int(count); i++ {
		args, err := copyProcessArguments(int(raw[i].pid))
		if err != nil {
			continue
		}
		result = append(result, ProcessInfo{
			PID:                  int(raw[i].pid),
			PPID:                 int(raw[i].ppid),
			UID:                  uint32(raw[i].uid),
			StartSeconds:         int64(raw[i].start_seconds),
			ExecutablePath:       C.GoString(&raw[i].executable_path[0]),
			ParentPath:           C.GoString(&raw[i].parent_path[0]),
			ParentCodeValid:      raw[i].parent_code_valid != 0,
			ParentCodeIdentifier: C.GoString(&raw[i].parent_code_identifier[0]),
			ParentCDHash:         C.GoString(&raw[i].parent_cdhash[0]),
			Arguments:            args,
		})
	}
	return result, nil
}

func copyProcessArguments(pid int) ([]string, error) {
	var data *C.uchar
	var dataLen C.size_t
	var errBuf [512]C.char
	if C.og_copy_process_args(C.int(pid), &data, &dataLen, &errBuf[0], C.size_t(len(errBuf))) != 0 {
		return nil, bridgeError(errBuf[:])
	}
	if data == nil || dataLen == 0 || dataLen > 1<<20 {
		if data != nil {
			C.og_free(unsafe.Pointer(data))
		}
		return nil, errors.New("invalid process argument buffer")
	}
	defer C.og_free(unsafe.Pointer(data))
	return parseKernProcArgs(C.GoBytes(unsafe.Pointer(data), C.int(dataLen)))
}

func parseKernProcArgs(data []byte) ([]string, error) {
	if len(data) < 4 {
		return nil, errors.New("process argument buffer is truncated")
	}
	argc := int(*(*int32)(unsafe.Pointer(&data[0])))
	if argc <= 0 || argc > 4096 {
		return nil, fmt.Errorf("invalid process argc %d", argc)
	}
	pos := 4
	for pos < len(data) && data[pos] != 0 {
		pos++
	}
	for pos < len(data) && data[pos] == 0 {
		pos++
	}

	args := make([]string, 0, argc)
	for len(args) < argc && pos < len(data) {
		start := pos
		for pos < len(data) && data[pos] != 0 {
			pos++
		}
		args = append(args, string(data[start:pos]))
		pos++
	}
	if len(args) != argc {
		return nil, fmt.Errorf("process argument buffer contains %d of %d arguments", len(args), argc)
	}
	return args, nil
}

func bridgeError(buf []C.char) error {
	if len(buf) == 0 || buf[0] == 0 {
		return errors.New("macOS bridge operation failed")
	}
	return errors.New(C.GoString(&buf[0]))
}
