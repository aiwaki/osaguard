package autotype

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

	"github.com/aiwaki/osaguard/internal/darwinbridge"
	basepolicy "github.com/aiwaki/osaguard/internal/policy"
)

const (
	PolicyPath     = "/Library/Application Support/OsaGuard/autotype-policy.json"
	MaxPolicyBytes = 64 << 10
	maxRules       = 32
)

var (
	ruleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	digestPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	cdhashPattern   = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
)

type Policy struct {
	Version                       int    `json:"version"`
	Account                       string `json:"account"`
	PollMilliseconds              int    `json:"poll_milliseconds,omitempty"`
	StableChecks                  int    `json:"stable_checks,omitempty"`
	ProcessMaxAgeSeconds          int    `json:"process_max_age_seconds,omitempty"`
	CooldownSeconds               int    `json:"cooldown_seconds,omitempty"`
	RequireSingleOsaScriptProcess *bool  `json:"require_single_osascript_process,omitempty"`
	Rules                         []Rule `json:"rules"`
	universalMode                 bool
}

type Rule struct {
	Name                 string `json:"name"`
	ArgumentsSHA256      string `json:"arguments_sha256"`
	ParentExecutable     string `json:"parent_executable"`
	ParentSHA256         string `json:"parent_sha256"`
	ParentCodeIdentifier string `json:"parent_code_identifier"`
	ParentCDHash         string `json:"parent_cdhash"`
	AuthContextSHA256    string `json:"auth_context_sha256"`
	ScriptFile           string `json:"script_file,omitempty"`
	ScriptFileSHA256     string `json:"script_file_sha256,omitempty"`
	SubmitAutomatically  *bool  `json:"submit_automatically,omitempty"`
	universalRequest     bool
}

type Fingerprint struct {
	PID                  int    `json:"pid"`
	ArgumentsSHA256      string `json:"arguments_sha256"`
	ParentExecutable     string `json:"parent_executable"`
	ParentSHA256         string `json:"parent_sha256"`
	ParentCodeIdentifier string `json:"parent_code_identifier"`
	ParentCDHash         string `json:"parent_cdhash"`
	ScriptFile           string `json:"script_file,omitempty"`
	ScriptFileSHA256     string `json:"script_file_sha256,omitempty"`
}

func Load(path string, requireRootOwned bool) (*Policy, error) {
	if requireRootOwned {
		if err := basepolicy.VerifyTrustedFile(path, false); err != nil {
			return nil, fmt.Errorf("untrusted autotype policy: %w", err)
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
		return nil, fmt.Errorf("autotype policy exceeds %d bytes", MaxPolicyBytes)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, err
	}
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode autotype policy: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := consumeJSON(dec, 0); err != nil {
		return fmt.Errorf("validate autotype JSON structure: %w", err)
	}
	return ensureEOF(dec)
}

func consumeJSON(dec *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
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
			if err := consumeJSON(dec, depth+1); err != nil {
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
			if err := consumeJSON(dec, depth+1); err != nil {
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

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("autotype policy contains multiple JSON values")
}

func (p *Policy) Validate() error {
	if p == nil || p.Version != 1 {
		return errors.New("autotype policy version must be 1")
	}
	if p.Account == "" || len(p.Account) > 128 || strings.ContainsAny(p.Account, "\x00\r\n") {
		return errors.New("account must be a non-empty single-line value of at most 128 bytes")
	}
	if p.universalMode && len(p.Rules) != 0 {
		return errors.New("universal mode must not contain enrolled rules")
	}
	if !p.universalMode && (len(p.Rules) == 0 || len(p.Rules) > maxRules) {
		return fmt.Errorf("autotype policy must contain 1 to %d rules", maxRules)
	}
	if p.PollMilliseconds != 0 && (p.PollMilliseconds < 50 || p.PollMilliseconds > 1000) {
		return errors.New("poll_milliseconds must be 50 to 1000, or 0 for 100")
	}
	if p.StableChecks != 0 && (p.StableChecks < 3 || p.StableChecks > 10) {
		return errors.New("stable_checks must be 3 to 10, or 0 for 3")
	}
	if p.ProcessMaxAgeSeconds != 0 && (p.ProcessMaxAgeSeconds < 3 || p.ProcessMaxAgeSeconds > 30) {
		return errors.New("process_max_age_seconds must be 3 to 30, or 0 for 15")
	}
	if p.CooldownSeconds != 0 && (p.CooldownSeconds < 10 || p.CooldownSeconds > 600) {
		return errors.New("cooldown_seconds must be 10 to 600, or 0 for 60")
	}
	seen := make(map[string]struct{}, len(p.Rules))
	seenMatch := make(map[string]string, len(p.Rules))
	for i, rule := range p.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		if _, ok := seen[rule.Name]; ok {
			return fmt.Errorf("duplicate rule name %q", rule.Name)
		}
		seen[rule.Name] = struct{}{}
		matchKey := ruleMatchKey(rule)
		if previous, ok := seenMatch[matchKey]; ok {
			return fmt.Errorf("rules %q and %q have the same authorization fingerprint", previous, rule.Name)
		}
		seenMatch[matchKey] = rule.Name
	}
	return nil
}

func (r Rule) Validate() error {
	if r.universalRequest {
		return errors.New("an operation-local universal rule cannot be serialized")
	}
	if !ruleNamePattern.MatchString(r.Name) {
		return fmt.Errorf("invalid rule name %q", r.Name)
	}
	for label, value := range map[string]string{
		"arguments_sha256":    r.ArgumentsSHA256,
		"parent_sha256":       r.ParentSHA256,
		"auth_context_sha256": r.AuthContextSHA256,
	} {
		if !digestPattern.MatchString(value) {
			return fmt.Errorf("%s must be a lowercase SHA-256 digest", label)
		}
	}
	if !cdhashPattern.MatchString(r.ParentCDHash) {
		return errors.New("parent_cdhash must be a 40- or 64-character lowercase code-directory hash")
	}
	if !filepath.IsAbs(r.ParentExecutable) || filepath.Clean(r.ParentExecutable) != r.ParentExecutable {
		return errors.New("parent_executable must be an absolute clean path")
	}
	if r.ParentCodeIdentifier == "" || len(r.ParentCodeIdentifier) > 128 || strings.ContainsAny(r.ParentCodeIdentifier, "\x00\r\n") {
		return errors.New("parent_code_identifier must be a non-empty single-line value of at most 128 bytes")
	}
	if (r.ScriptFile == "") != (r.ScriptFileSHA256 == "") {
		return errors.New("script_file and script_file_sha256 must be set together")
	}
	if r.ScriptFile != "" {
		if !filepath.IsAbs(r.ScriptFile) || filepath.Clean(r.ScriptFile) != r.ScriptFile {
			return errors.New("script_file must be an absolute clean path")
		}
		if !digestPattern.MatchString(r.ScriptFileSHA256) {
			return errors.New("script_file_sha256 must be a lowercase SHA-256 digest")
		}
	}
	return nil
}

func (p *Policy) EffectivePollMilliseconds() int {
	if p.PollMilliseconds == 0 {
		return 100
	}
	return p.PollMilliseconds
}
func (p *Policy) EffectiveStableChecks() int {
	if p.StableChecks == 0 {
		return 3
	}
	return p.StableChecks
}
func (p *Policy) EffectiveProcessMaxAgeSeconds() int {
	if p.ProcessMaxAgeSeconds == 0 {
		return 15
	}
	return p.ProcessMaxAgeSeconds
}
func (p *Policy) EffectiveCooldownSeconds() int {
	if p.CooldownSeconds == 0 {
		return 60
	}
	return p.CooldownSeconds
}
func (p *Policy) RequiresSingleOsaScriptProcess() bool {
	return p.RequireSingleOsaScriptProcess == nil || *p.RequireSingleOsaScriptProcess
}
func (r Rule) ShouldSubmitAutomatically() bool {
	return r.SubmitAutomatically == nil || *r.SubmitAutomatically
}

// NewUniversalPolicy creates an in-memory-only policy that accepts every new
// /usr/bin/osascript process owned by the current user. It deliberately cannot
// be decoded from or marshaled to a policy file: enabling this mode must be an
// explicit command-line decision because it provides passwordless administrator
// approval to any process already running as that user.
func NewUniversalPolicy(account string) *Policy {
	return &Policy{Version: 1, Account: account, universalMode: true}
}

func (p *Policy) IsUniversal() bool {
	return p != nil && p.universalMode
}

func FingerprintProcess(process darwinbridge.ProcessInfo) (Fingerprint, error) {
	if process.ExecutablePath != "/usr/bin/osascript" || process.PID <= 0 || len(process.Arguments) == 0 {
		return Fingerprint{}, errors.New("process is not a complete /usr/bin/osascript process")
	}
	if process.ParentPath == "" || !filepath.IsAbs(process.ParentPath) {
		return Fingerprint{}, errors.New("osascript parent path is unavailable")
	}
	if !process.ParentCodeValid || process.ParentCodeIdentifier == "" || !cdhashPattern.MatchString(process.ParentCDHash) {
		return Fingerprint{}, errors.New("osascript parent process has no valid code identity")
	}
	parentDigest, err := hashRegularFile(process.ParentPath)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("hash parent executable: %w", err)
	}
	fingerprint := Fingerprint{
		PID:                  process.PID,
		ArgumentsSHA256:      hashArguments(process.Arguments),
		ParentExecutable:     process.ParentPath,
		ParentSHA256:         parentDigest,
		ParentCodeIdentifier: process.ParentCodeIdentifier,
		ParentCDHash:         process.ParentCDHash,
	}
	scriptFile, err := scriptFileFromArguments(process.Arguments)
	if err != nil {
		return Fingerprint{}, err
	}
	if scriptFile != "" {
		if err := basepolicy.VerifyTrustedFile(scriptFile, false); err != nil {
			return Fingerprint{}, fmt.Errorf("osascript file is not root-trusted: %w", err)
		}
		digest, err := hashRegularFile(scriptFile)
		if err != nil {
			return Fingerprint{}, fmt.Errorf("hash osascript file: %w", err)
		}
		fingerprint.ScriptFile = scriptFile
		fingerprint.ScriptFileSHA256 = digest
	}
	return fingerprint, nil
}

func (p *Policy) Match(process darwinbridge.ProcessInfo) (*Rule, error) {
	if p.universalMode {
		if process.ExecutablePath != "/usr/bin/osascript" || process.PID <= 0 || len(process.Arguments) == 0 {
			return nil, errors.New("process is not a complete /usr/bin/osascript process")
		}
		if process.UID != uint32(os.Getuid()) {
			return nil, errors.New("osascript process is not owned by the current user")
		}
		if process.ParentPath == "" || !filepath.IsAbs(process.ParentPath) {
			return nil, errors.New("osascript parent path is unavailable")
		}
		return &Rule{
			Name:                 "universal-request",
			ArgumentsSHA256:      hashArguments(process.Arguments),
			ParentExecutable:     process.ParentPath,
			ParentCodeIdentifier: process.ParentCodeIdentifier,
			ParentCDHash:         process.ParentCDHash,
			universalRequest:     true,
		}, nil
	}
	fingerprint, err := FingerprintProcess(process)
	if err != nil {
		return nil, err
	}
	for i := range p.Rules {
		rule := &p.Rules[i]
		if rule.ArgumentsSHA256 == fingerprint.ArgumentsSHA256 &&
			rule.ParentExecutable == fingerprint.ParentExecutable &&
			rule.ParentSHA256 == fingerprint.ParentSHA256 &&
			rule.ParentCodeIdentifier == fingerprint.ParentCodeIdentifier &&
			rule.ParentCDHash == fingerprint.ParentCDHash &&
			rule.ScriptFile == fingerprint.ScriptFile &&
			rule.ScriptFileSHA256 == fingerprint.ScriptFileSHA256 {
			return rule, nil
		}
	}
	return nil, nil
}

func SuggestedRule(name string, fingerprint Fingerprint, authContextSHA256 string) Rule {
	return Rule{
		Name:                 name,
		ArgumentsSHA256:      fingerprint.ArgumentsSHA256,
		ParentExecutable:     fingerprint.ParentExecutable,
		ParentSHA256:         fingerprint.ParentSHA256,
		ParentCodeIdentifier: fingerprint.ParentCodeIdentifier,
		ParentCDHash:         fingerprint.ParentCDHash,
		AuthContextSHA256:    authContextSHA256,
		ScriptFile:           fingerprint.ScriptFile,
		ScriptFileSHA256:     fingerprint.ScriptFileSHA256,
	}
}

func MarshalSuggestedPolicy(account string, rules []Rule) ([]byte, error) {
	p := Policy{Version: 1, Account: account, Rules: rules}
	return MarshalPolicy(&p)
}

func AppendRule(p *Policy, rule Rule) (*Policy, error) {
	if p == nil {
		return nil, errors.New("autotype policy is nil")
	}
	if p.universalMode {
		return nil, errors.New("cannot append an enrolled rule to universal mode")
	}
	updated := *p
	updated.Rules = append(append([]Rule(nil), p.Rules...), rule)
	if err := updated.Validate(); err != nil {
		return nil, err
	}
	return &updated, nil
}

func MarshalPolicy(p *Policy) ([]byte, error) {
	if p != nil && p.universalMode {
		return nil, errors.New("universal mode is in-memory only and cannot be serialized")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	copyPolicy := *p
	copyPolicy.Rules = append([]Rule(nil), p.Rules...)
	sort.Slice(copyPolicy.Rules, func(i, j int) bool { return copyPolicy.Rules[i].Name < copyPolicy.Rules[j].Name })
	return json.MarshalIndent(copyPolicy, "", "  ")
}

func ruleMatchKey(rule Rule) string {
	return strings.Join([]string{
		rule.ArgumentsSHA256,
		rule.ParentExecutable,
		rule.ParentSHA256,
		rule.ParentCodeIdentifier,
		rule.ParentCDHash,
		rule.ScriptFile,
		rule.ScriptFileSHA256,
		rule.AuthContextSHA256,
	}, "\x00")
}

func hashArguments(arguments []string) string {
	h := sha256.New()
	for _, argument := range arguments {
		_, _ = h.Write([]byte(argument))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashRegularFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("path is not a regular non-symlink file")
	}
	if info.Size() > 1<<30 {
		return "", errors.New("file exceeds 1 GiB hash limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func scriptFileFromArguments(arguments []string) (string, error) {
	if len(arguments) < 2 {
		return "", errors.New("stdin-fed osascript is not eligible for autotype")
	}
	hasInlineSource := false
	for i := 1; i < len(arguments); i++ {
		arg := arguments[i]
		switch arg {
		case "-e":
			hasInlineSource = true
			i++
			if i >= len(arguments) {
				return "", errors.New("osascript -e is missing its source")
			}
		case "-l", "-s":
			i++
			if i >= len(arguments) {
				return "", fmt.Errorf("osascript %s is missing its value", arg)
			}
		case "-i":
			continue
		case "-":
			return "", errors.New("stdin-fed osascript is not eligible for autotype")
		default:
			if strings.HasPrefix(arg, "-") {
				return "", fmt.Errorf("unsupported osascript option %q", arg)
			}
			if hasInlineSource {
				return "", nil
			}
			if !filepath.IsAbs(arg) || filepath.Clean(arg) != arg {
				return "", errors.New("osascript file must use an absolute clean path")
			}
			return arg, nil
		}
	}
	if hasInlineSource {
		return "", nil
	}
	return "", errors.New("stdin-fed osascript is not eligible for autotype")
}
