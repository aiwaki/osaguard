# OsaGuard security design

## Current product decision

After explicit setup, the menu-bar app automatically submits administrator
dialogs created through `/usr/bin/osascript`. It is not bound to a particular
application or an allowlist of operations.

That convenience is also the central security limitation. After the user saves
their administrator password and enables automatic confirmation, any process
already running as that macOS user can start a genuine AppleScript administrator
request. OsaGuard can then enter and submit the password. OsaGuard is therefore a
**passwordless-root oracle for same-user code**, including malware. Verifying the
Apple authorization UI prevents several misdelivery and fake-window attacks; it
does not restore human authorization of the requested operation or prove which
client caused a particular genuine authorization window.

The warning and explicit acknowledgement are required before automation starts.
Choosing **Not now** is valid: OsaGuard remains unconfigured and does not enter
passwords.

## Current runtime architecture

1. **Tauri application.** `/Applications/OsaGuard.app` is an unprivileged Tauri
   v2 menu-bar application. It has a WebView for setup, status, warnings, and
   preferences, and uses macOS accessory activation so it does not need a Dock
   icon.
2. **Accessibility owner.** The native Tauri main process calls the macOS
   Accessibility trust API and displays the system permission request. This is
   deliberately done by the installed app process.
3. **In-process Go bridge.** Cargo invokes `build.rs`, which builds the native
   Go bridge as a C archive and statically links it into `osaguard-tray`. Rust
   calls its narrow C ABI. When automatic confirmation is enabled, the Go
   watcher runs on a Rust-owned worker thread in that same app process; closing
   a private control pipe cancels it. The production bundle's `Contents/MacOS`
   contains only `osaguard-tray`.
4. **Login startup.** Tauri registers the OsaGuard application itself to start at
   login. There is no separate watcher executable or LaunchAgent in the current
   architecture.
   At startup OsaGuard unloads and removes the obsolete
   `dev.aiwaki.osaguard.autotype` watcher LaunchAgent left by older development
   builds.
5. **Password enrollment.** The setup WebView requests password enrollment but
   never receives a password. The linked Go bridge presents a native AppKit
   secure-text dialog and writes the result to the user's login Keychain. The
   password bytes remain in Go/native code and never cross the C ABI or pass
   through JavaScript, Tauri IPC, command arguments, environment variables,
   logs, or the clipboard.
6. **Password use.** The Tauri UI checks Keychain item presence through
   metadata-only bridge calls. Only the linked Go code retrieves secret bytes,
   after the watcher has completed its final process and authorization-UI checks.

The app and linked bridge invoke no shell in this path. The WebView cannot
choose an executable path, watcher account, or native bridge operation.

## Secret-handling invariants

- The password may exist only in the native secure-text control, the user's login
  Keychain, and short-lived native buffers used to store or inject it.
- Password buffers are memory-locked where available, never converted to Go
  strings, and explicitly zeroed. The UTF-16 injection buffer is also zeroed.
- The live app process disables core dumps and debugger attachment before the
  watcher can retrieve the secret.
- The WebView can request **store**, **replace**, or **delete**, but cannot read,
  display, export, or receive the saved value.
- Password input is not placed in `argv`, the environment, standard streams,
  logs, or the clipboard.
- Re-enrollment updates the existing OsaGuard Keychain item with `SecItemUpdate`.
  Cancel is a successful no-op, and a failed update leaves the previous secret
  intact instead of deleting it first.
- User-requested password removal and uninstall delete every generic-password
  item in OsaGuard's dedicated service that belongs to the current OsaGuard
  executable, not just the installed user's current account label. Each
  candidate must first prove the caller-only OsaGuard ACL; an ambiguous,
  poisoned, or differently trusted same-service item fails removal before any
  verified item is deleted. This never changes the user's Keychain search list
  or default Keychain. A native deletion failure is surfaced and retains the
  existing lifecycle rollback behavior rather than claiming all secrets were
  removed.

The current Keychain integration uses the file-based macOS Keychain with an
explicit caller ACL. There is no released public app identity today. Local
ad-hoc builds do not provide a cross-version identity guarantee, so a future
Apple-signed release must separately qualify TCC and Keychain continuity before
it can claim retained setup. A future release may evaluate migration to the
data-protection Keychain.

## Authorization-dialog checks

OsaGuard does not type into a generic focused password field. Before retrieving
the secret it requires, among other checks:

- a newly observed, same-user `/usr/bin/osascript` process;
- exactly one eligible `osascript` process during the request;
- a young process whose PID, start time, arguments, parent path, and live parent
  code-signing identity remain unchanged;
- the exact Apple SecurityAgent executable and a valid Apple signing anchor;
- one visible, enabled, focused, empty secure-text field;
- repeated stable reads of the same authorization PID and UI context;
- an unlocked user session, a cooldown, and the hardware Escape interlock.

The UI context learned for an automatic request is local to that operation and
must remain stable before password retrieval, before targeted text injection,
and before Return. Text and Return are posted to the verified SecurityAgent PID,
not to the global event tap.

These controls reduce accidental typing, focus-stealing, stale-dialog, and
simple fake-window risks. They cannot determine whether the requested shell
command is safe. A malicious but genuine new `osascript` request is intentionally
eligible after automatic confirmation is enabled.

### Unavoidable requester-to-dialog causality limit

Public macOS Accessibility and CGWindow APIs expose the SecurityAgent process
that owns an administrator dialog. They do not expose the requesting client or
provide a cryptographic or OS-enforced binding between a particular
`osascript` process and a particular SecurityAgent window. OsaGuard therefore
uses only short, best-effort temporal correlation between a newly observed
eligible request and a stable genuine SecurityAgent UI.

Consequently, a different genuine SecurityAgent administrator dialog that
appears in the same short matching window can receive the saved password. The
Apple signature, PID-targeted delivery, repeated snapshots, and single-request
gates do not close this causal gap. The product must never claim stronger
client-to-dialog attribution.

## Realistic attacker stories

- **Same-user code starts an arbitrary privileged AppleScript.** After setup,
  this is eligible and may obtain administrator execution. This is the
  passwordless-root-oracle warning, not a scenario the UI checks can prevent.
- **Same-user malware draws a fake password window or steals focus.** The fake
  process lacks Apple's SecurityAgent identity, and targeted PID delivery does
  not follow global focus.
- **The operation or authorization window changes during checking.** Repeated
  process, signing, field, PID, and context checks reject the request before
  secret retrieval or Return.
- **Multiple authorization requests race.** Single-process gating and stable
  context checks reduce misassociation, but a different genuine SecurityAgent
  dialog within the same short correlation window can receive the password.
- **The WebView is compromised.** It can invoke the narrow commands exposed by
  Tauri, including replacing or deleting the Keychain item and pausing or
  enabling automation after the saved acknowledgement. It cannot obtain secret
  bytes through the defined IPC interface. This does not eliminate automatic
  confirmation's root-oracle risk.
- **A root process or the kernel is compromised.** This is out of scope; root
  already controls OsaGuard, TCC state, and credential material.

## Accessibility and signing identity

macOS requires a one-time user decision for Accessibility. OsaGuard cannot and
must not approve itself. The installed Tauri main process makes the native trust
request, and the statically linked watcher operates in that same app process.

Source and ordinary CI builds are ad-hoc signed and are not notarized. **Each
local ad-hoc rebuild can have a new code identity from TCC's perspective**, even
when its bundle identifier and path are unchanged. There is no public OsaGuard
DMG, updater archive, or continuity claim across versions. A self-signed
certificate, locally trusted identity, or Finder bypass must never be used as a
replacement for Developer ID signing and notarization.

The source includes a Tauri updater implementation, but it remains in
test-build/fail-closed mode until a future Apple-signed, notarized channel has
passed full artifact and `N → N+1` continuity qualification. See
[Releasing OsaGuard](RELEASING.md) for that hard gate.

## Advanced exact-rule CLI (separate capability)

The repository still contains exact-action and exact-autotype policy tooling for
development and security qualification. It is separate from the release app
behavior described above and is not required by the public onboarding flow.

In exact-rule mode, `enroll-next` captures a specific operation fingerprint,
including arguments, parent executable and live signing identity, optional
script hash, and authorization UI context. Private mode-0600 drafts can contain
multiple rules. Promotion to the legacy root-owned policy path is an explicit
`sudo` boundary, and exact rules fail closed when their enrolled fingerprints do
not match.

The older privileged-action runner and sudoers allowlist are likewise separate
advanced/legacy capabilities. Claims about root-owned policies, fixed privileged
actions, and sudoers grants apply only to those CLI modes; they are not security
properties of the release app's automatic confirmation.

The legacy CLI's `forget-password` action removes all caller-only password
records that the same CLI executable can verify, regardless of account label.
It intentionally rejects `--account` rather than presenting a targeted delete
as complete. The public app does not delete an item trusted to a different
executable; a developer must run `forget-password` from that original CLI
binary before discarding it.

## Residual risk

Automatic confirmation deliberately trades fresh human approval for zero-touch
operation. Keychain storage, stable process checks, Apple signature validation,
targeted injection, memory hardening, and TCC process ownership raise the bar for
credential theft and misdelivery. They do not make arbitrary same-user code safe
and do not narrow what a genuine AppleScript administrator request can execute.

Do not enable OsaGuard on a shared, managed, or otherwise untrusted Mac. This
same-user passwordless-root risk is a defining limitation of unattended
administrator confirmation, not a setting that process validation can remove.

## Primary references

- [Apple: Accessibility permission settings](https://support.apple.com/guide/mac-help/-mh43185/mac)
- [Apple: AppleScript `do shell script`](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/reference/ASLR_cmds.html)
- [Apple: Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [Apple: Keychain and Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [`makc` keyboard and mouse control](https://github.com/aiwaki/makc)
