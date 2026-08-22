# OsaGuard qualification record

## Distribution status

This is source, local-development, and preview-publication qualification
evidence. OsaGuard has no Apple Developer Program membership, Developer ID
Application certificate, or notarization ticket. Public preview builds are not
a stable channel. `0.1.3-preview.1` is the manually installed bridge to a
self-signed preview identity and a separately signed Tauri updater channel. See
[Releasing OsaGuard](RELEASING.md) for the exact boundary.

## 2026-08-13 — macOS 26.5.2 (25F84), Apple Silicon

Environment:

- Go 1.26.2, project language level Go 1.23
- Xcode toolchain at `/Applications/Xcode.app/Contents/Developer`
- `makc` v0.2.0 (`31d0078d4ad8f3c10423016974a698280c2939f2`)

## Scope

The current product is a Tauri menu-bar app with a setup WebView and an
explicitly enabled universal watcher. Cargo builds the Go native bridge as a C
archive and statically links it into `osaguard-tray`; the watcher runs on a
Rust-owned worker thread inside that single app process.

Some evidence below covers the advanced exact-rule CLI retained in the
repository. That evidence is useful for the shared SecurityAgent and targeted
injection code, but exact-rule policies, root-owned installation, and sudoers
are **not** properties of the universal menu-bar app mode.

## Current Tauri application

The Tauri v2 app was qualified with these current architectural properties:

- bundle identifier `dev.aiwaki.osaguard`;
- accessory/menu-bar activation with no normal Dock presence;
- a WebView for setup, status, warnings, and preferences;
- no password value in WebView state or Tauri IPC;
- a native Accessibility request made by the Tauri main process;
- the Go bridge statically linked into `osaguard-tray`, with that as the only
  executable in the production bundle's `Contents/MacOS`;
- the Go watcher invoked through a narrow C ABI on one Rust-owned worker thread,
  with duplicate workers suppressed and completed workers joined;
- the Tauri app, rather than the watcher, is registered to start at login;
- the obsolete `dev.aiwaki.osaguard.autotype` watcher LaunchAgent is unloaded
  and removed on startup;
- single-instance behavior and a template menu-bar icon;
- hardened-runtime app bundling and successful
  `codesign --verify --deep --strict` for the local ad-hoc build.

Rust tests and `cargo clippy --all-targets --all-features -- -D warnings` passed
for this implementation. The local app is ad-hoc signed and is not notarized.

### Preview identity; no stable release identity

An ad-hoc local rebuild has a new code identity from TCC's perspective.
Accessibility must be tested only after removing the old OsaGuard row,
installing the rebuilt app in `/Applications`, launching that exact app,
requesting access again, and enabling the new row. An old enabled-looking row
is not proof that the rebuilt app is trusted.

No stable public release identity is provisioned. A self-signed certificate,
ad-hoc signature, local trust change, or Finder contextual Open is not a
substitute for Developer ID signing and notarization. The old `0.1.2` GitHub
preview is ad-hoc and makes no TCC/Keychain-continuity claim. The first
persistent self-signed identity build is `0.1.3-preview.1`; continuity is not
claimed until a real update to a later preview proves it.

Preview-update qualification also requires a replay test in which otherwise
signature-verified archive bytes contain an older bundle version. OsaGuard must
reject those bytes before stopping the watcher. Archive qualification covers
compressed and expanded size limits, entry-count and path limits, duplicate or
missing `Info.plist`, the exact bundle identifier, and the selected version.

## Universal watcher checks

Unit and race tests cover the universal-mode behavior that differs from exact
rules:

- startup logs an explicit passwordless-administrator warning;
- existing `osascript` processes are ignored;
- a request must remain the same PID, start time, arguments, parent path, and
  live parent code-signing identity throughout the operation;
- the authorization context is learned for that one request, must be complete,
  and must remain stable before secret retrieval and targeted injection;
- a changed authorization context is rejected before Keychain retrieval;
- the universal request must still refer to the same operation process before
  text and Return are sent.

These tests validate consistency and misdelivery defenses. They do not narrow
the command being authorized: after setup, any same-user process can
deliberately create a new genuine `/usr/bin/osascript` administrator request.

## Real Apple authorization UI recognition

A non-destructive request was opened and left unsubmitted:

```sh
/usr/bin/osascript -e 'do shell script "/usr/bin/id -u" with administrator privileges'
```

`osaguard inspect-auth` observed:

- exact executable:
  `/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent`;
- signing identifier `com.apple.SecurityAgent`, with valid `anchor apple`;
- one on-screen, enabled, focused `AXSecureTextField`;
- stable authorization-context SHA-256
  `81497fb731d8ab7938ca6229728e82a34c5305eec4feb365f886d34b6c5ae3b0`;
- window title `Untitled`; no localized title matching is used.

After the SecurityAgent UI finished appearing, three stable checks passed and a
dry run reported that it would target the exact SecurityAgent PID. It did not
retrieve or type a password. This earlier standalone CLI test used Accessibility
available through the Codex host; it is not evidence that a newly rebuilt
`OsaGuard.app` has its own current TCC grant.

## Target-PID injection

The gated integration test
`TestTargetedInjectionIntoLiveAuthorizationField` posted the literal test
character `X` to the observed SecurityAgent PID with `CGEventPostToPid`. The AX
secure-field length changed from 0 to 1 in that same PID. Return was not sent;
the request was canceled. This proves targeted delivery without using or
validating the user's password.

## Keychain and native password window

An earlier, historical qualification used `TestKeychainRoundTripIntegration` to
create an isolated generic-password item containing `not-a-real-password`,
retrieve and compare it, zero the returned buffer, verify metadata-only
presence, delete the item, and verify absence. It did not use an administrator
credential. That test was deliberately removed: production Keychain calls use
the active user's login Keychain when no test-only selector is supplied, so no
ordinary development or CI test may touch it. Equivalent live qualification now
belongs only in a disposable macOS account or VM; see
[`internal/darwinbridge/KEYCHAIN_TESTING.md`](../internal/darwinbridge/KEYCHAIN_TESTING.md).

The current setup command presents an AppKit `NSSecureTextField` with password
confirmation in the linked Go bridge. The Tauri WebView only requests this
native action and receives completion status; secret bytes remain in Go/native
code and are not passed through the Rust/Go ABI, JavaScript, IPC, command
arguments, environment variables, logs, or the clipboard.

## Advanced exact-rule CLI qualification

The following results apply only to the separate exact-rule capability.

### Bounded next-request enrollment

`enroll-next` was started with an empty `osascript` baseline and a 30-second
timeout. The non-destructive `/usr/bin/id -u` authorization request was then
opened. Enrollment waited through incomplete UI state, required three stable
secure-field snapshots, repeated the process fingerprint and UI checks, and
created a mode-`0600` policy containing the expected arguments, parent file,
runtime signing identity/CDHash, and UI-context hashes. The generated policy
passed `validate-autotype-policy`. No password was retrieved or typed.

The multi-rule workflow was qualified with two different live requests:
`/usr/bin/id -u` created the initial private draft and `/usr/bin/id -un` was
captured with `--append-to`. Atomic same-directory replacement preserved a
mode-0600 draft, both argument hashes remained present, and
`validate-autotype-policy` accepted the two-rule policy.

A negative control changed only the enrolled command from `/usr/bin/id -u` to
`/usr/bin/id -un`. The exact-rule watcher produced no recognition or injection
event during its 15-second eligibility window. This proves exact matching for
that advanced mode; the release app intentionally does not provide this
restriction.

### Runtime caller identity

Enrollment and the final exact-mode pre-injection check bind the live parent
process to its Security-framework-validated signing identifier and CDHash in
addition to executable path and file SHA-256. A dry run enrolled the live
Homebrew `rtk` caller as identifier `rtk-69b28a339bfc427d` with CDHash
`23d92d97a43037bf7af6a682e4fd14fc19eb39c8`; the watcher recognized the exact
request and reported the SecurityAgent PID without retrieving or typing a
password.

## Automated checks

- `go test -race ./...`: passed, including universal and exact-rule watcher tests
- `go vet ./...`: passed
- non-cgo Go tests: passed
- action-policy and autotype-policy decoder fuzzing: passed; both readers cap
  input before allocation and reject JSON nesting deeper than 64 levels
- action and autotype JSON reject unknown and duplicate keys
- generated legacy sudoers fragment: `visudo -cf` passed
- Rust tests, formatting, and clippy with warnings denied: passed
- npm audit at high severity: passed
- shell and plist syntax checks: passed
- local app bundle: ad-hoc hardened-runtime signing and strict deep code-signature
  verification passed

## Remaining live gates

An end-to-end real-password run is intentionally not recorded. For the current
architecture it requires the user to:

1. remove any stale OsaGuard Accessibility row left by an earlier ad-hoc build;
2. grant Accessibility to the exact installed `/Applications/OsaGuard.app`;
3. store the password through the native secure window;
4. acknowledge the security warning and enable automatic confirmation;
5. observe the in-process watcher handle a controlled intended AppleScript
   request while no competing authorization dialog is present, and verify that
   unsupported, ambiguous, non-Apple, and non-empty dialogs remain rejected.

This live gate must also confirm that setup status advances after the Tauri main
process receives the new TCC grant. It must not be performed by automation with
the user's real password.

The public preview workflow builds on a GitHub-hosted runner, imports only the
persistent self-signed preview P12 into a disposable Keychain, signs the app,
and removes that Keychain. It also signs a Tauri updater archive with a separate
persistent key, verifies the signature offline, and publishes exact-tag
metadata, checksums, and attestations after successful exact-main CI. Neither
identity is an Apple credential or a shippable stable identity.

The remaining stable-channel gates are Developer ID signing, Apple notarization
and stapling, a reviewed updater key and endpoint, a protected draft release,
and physical first-install/N → N+1 canaries on Apple Silicon and Intel. Those
canaries must cover native notification and tray fallback, explicit install
confirmation, restart, offline and corrupted-payload failures, watcher recovery,
and retained Accessibility/Keychain access before any password is re-saved. The
exact stable procedure is in [Releasing OsaGuard](RELEASING.md); none of those
gates is claimed by preview signing alone.
