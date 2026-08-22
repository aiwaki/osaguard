package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

const (
	MaxPolicyBytes = 64 << 10
	MaxActions     = 64
	MaxArguments   = 32
)

var (
	actionNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	sha256Pattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	forbiddenTools    = map[string]struct{}{
		"bash": {}, "dash": {}, "env": {}, "fish": {}, "ksh": {},
		"node": {}, "open": {}, "osascript": {}, "perl": {}, "php": {},
		"python": {}, "python3": {}, "ruby": {}, "sh": {}, "sudo": {},
		"zsh": {},
	}
)

type Policy struct {
	Version int               `json:"version"`
	Actions map[string]Action `json:"actions"`
}

type Action struct {
	Description    string   `json:"description,omitempty"`
	Executable     string   `json:"executable"`
	Arguments      []string `json:"arguments,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
	SHA256         string   `json:"sha256,omitempty"`
}

func Load(path string, requireRootOwned bool) (*Policy, error) {
	if requireRootOwned {
		if err := VerifyTrustedFile(path, false); err != nil {
			return nil, fmt.Errorf("untrusted policy file: %w", err)
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return Decode(io.LimitReader(f, MaxPolicyBytes+1))
}

func Decode(r io.Reader) (*Policy, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxPolicyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxPolicyBytes {
		return nil, fmt.Errorf("policy exceeds %d bytes", MaxPolicyBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, err
	}

	var p Policy
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := consumeJSONValue(dec, 0); err != nil {
		return fmt.Errorf("validate JSON structure: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return err
	}
	return nil
}

func consumeJSONValue(dec *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("object is not terminated")
		}
		return nil
	case '[':
		for dec.More() {
			if err := consumeJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("array is not terminated")
		}
		return nil
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing data: %w", err)
	}
	return errors.New("policy contains multiple JSON values")
}

func (p *Policy) Validate() error {
	if p == nil {
		return errors.New("policy is nil")
	}
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", p.Version)
	}
	if len(p.Actions) == 0 {
		return errors.New("policy must define at least one action")
	}
	if len(p.Actions) > MaxActions {
		return fmt.Errorf("policy defines more than %d actions", MaxActions)
	}

	for name, action := range p.Actions {
		if !actionNamePattern.MatchString(name) {
			return fmt.Errorf("invalid action name %q", name)
		}
		if err := action.Validate(); err != nil {
			return fmt.Errorf("action %q: %w", name, err)
		}
	}
	return nil
}

func (a Action) Validate() error {
	if a.Executable == "" || !filepath.IsAbs(a.Executable) {
		return errors.New("executable must be an absolute path")
	}
	if filepath.Clean(a.Executable) != a.Executable {
		return errors.New("executable path must already be clean")
	}
	if _, forbidden := forbiddenTools[filepath.Base(a.Executable)]; forbidden {
		return fmt.Errorf("generic interpreter or launcher %q is forbidden", filepath.Base(a.Executable))
	}
	if len(a.Arguments) > MaxArguments {
		return fmt.Errorf("more than %d arguments", MaxArguments)
	}
	for i, arg := range a.Arguments {
		if strings.IndexByte(arg, 0) >= 0 {
			return fmt.Errorf("argument %d contains NUL", i)
		}
		if len(arg) > 4096 {
			return fmt.Errorf("argument %d exceeds 4096 bytes", i)
		}
	}
	if a.TimeoutSeconds < 0 || a.TimeoutSeconds > 300 {
		return errors.New("timeout_seconds must be between 1 and 300, or 0 for the 30-second default")
	}
	if a.SHA256 != "" && !sha256Pattern.MatchString(a.SHA256) {
		return errors.New("sha256 must be 64 lowercase hexadecimal characters")
	}
	if !isAppleSystemPath(a.Executable) && a.SHA256 == "" {
		return errors.New("non-system executables require a sha256 pin")
	}
	return nil
}

func isAppleSystemPath(path string) bool {
	for _, prefix := range []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (p *Policy) ActionNames() []string {
	names := make([]string, 0, len(p.Actions))
	for name := range p.Actions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (a Action) EffectiveTimeoutSeconds() int {
	if a.TimeoutSeconds == 0 {
		return 30
	}
	return a.TimeoutSeconds
}

func VerifyExecutable(action Action) error {
	if err := VerifyTrustedFile(action.Executable, true); err != nil {
		return err
	}
	if action.SHA256 == "" {
		return nil
	}
	f, err := os.Open(action.Executable)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != action.SHA256 {
		return fmt.Errorf("sha256 mismatch: got %s", actual)
	}
	return nil
}

// VerifyTrustedFile rejects symlinks, non-root ownership, and files or parent
// directories writable by group/other. For policy files, executable may be
// false; all other trust checks stay the same.
func VerifyTrustedFile(path string, executable bool) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("target must be a regular file, not a symlink")
	}
	if executable && info.Mode().Perm()&0111 == 0 {
		return errors.New("executable has no execute bit")
	}
	if err := verifyRootOwnedMode(path, info); err != nil {
		return err
	}

	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("parent %q is not a real directory", dir)
		}
		if err := verifyRootOwnedMode(dir, info); err != nil {
			return err
		}
		if dir == "/" {
			break
		}
	}
	return nil
}

func verifyRootOwnedMode(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect ownership of %q", path)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("%q is not owned by root", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%q is writable by group or other", path)
	}
	return nil
}
