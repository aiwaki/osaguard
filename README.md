<div align="center">

<img src="app-tauri/icon.png" width="144" height="144" alt="OsaGuard app icon">

# OsaGuard

**English** · [Русский](README.ru.md)

[![macOS 13+](https://img.shields.io/badge/macOS-13%2B-000000?logo=apple)](#requirements)
[![Public preview](https://img.shields.io/badge/release-public_preview-f0a64a)](https://github.com/aiwaki/osaguard/releases)
[![CI](https://github.com/aiwaki/osaguard/actions/workflows/ci.yml/badge.svg)](https://github.com/aiwaki/osaguard/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Let supported AppleScript administrator prompts complete without typing your password every time.**

</div>

OsaGuard is a small macOS menu-bar app. After one-time setup, it recognizes the
supported administrator-password dialog opened by `osascript`, enters the
password stored in your macOS Keychain, and confirms the dialog.

There is no app or command allowlist: the behavior is intentionally universal
for supported `osascript` authorization dialogs. Read the [security warning](#security-warning)
before enabling it.

## Requirements

- macOS 13 Ventura or later;
- an Apple Silicon Mac for the current public preview;
- an administrator account whose password you know;
- permission to add OsaGuard under **System Settings → Privacy & Security → Accessibility**.

OsaGuard is currently a public preview. Release builds use a persistent
self-signed macOS code-signing identity, but they are not signed with Apple
Developer ID and are not notarized because the project does not yet use the
paid Apple Developer Program. You do **not** need an Apple Developer account to
install or use it.

## Install

1. Open the newest [OsaGuard **Pre-release**](https://github.com/aiwaki/osaguard/releases).
2. Download the Apple Silicon `.dmg` and open it.
3. Open OsaGuard from the disk image. On the first screen, choose **Install
   OsaGuard in Applications**. OsaGuard copies itself to `/Applications` and
   reopens the installed copy.
4. From then on, open `/Applications/OsaGuard.app` or use its menu-bar icon.

If macOS blocks the unnotarized preview, try to open it once, then open **System
Settings → Privacy & Security**, scroll to **Security**, choose **Open Anyway**
for OsaGuard, and confirm **Open**. On macOS versions that offer it, Finder’s
Control-click → **Open** for this exact copy is another route. Do not disable
Gatekeeper globally, and continue only if you downloaded OsaGuard from this
repository and trust it.

If OsaGuard is already running from `/Applications`, it is installed; the
install action is no longer needed. Installing an older version over a newer
one is refused.

## One-time setup

OsaGuard guides you through three steps; no Terminal commands are required.

1. **Allow Accessibility.** OsaGuard opens the correct System Settings page.
   Turn OsaGuard on there, then return to the app. macOS does not let an app
   grant this permission to itself.
2. **Save the administrator password.** Entry happens in a native secure macOS
   dialog. The password is written to Keychain by the native helper; it never
   enters the web interface, clipboard, command arguments, environment
   variables, analytics, or logs. Canceling is a quiet no-op and keeps the
   previous password.
3. **Review the warning and enable automatic mode.** This step is optional
   until you want automatic confirmation. The earlier permissions are required
   for the feature to work, not a promise that you must enable it.

The interface follows the system language: Russian on a Russian-language Mac,
English for every other language.

## What OsaGuard handles

OsaGuard is intended for the standard administrator-password dialog created by
`/usr/bin/osascript`, normally by AppleScript's `with administrator privileges`.
It is not tied to one application, so different supported confirmations may be
handled at different times.

It does **not** fill:

- the Mac login or lock screen;
- FileVault, website, browser, or application passwords;
- arbitrary secure text fields;
- every kind of macOS authentication dialog.

OsaGuard lives in the menu bar and normally has no permanent Dock icon. Its
menu provides status, **Open OsaGuard…**, **Save administrator password…** or
**Change saved password…**, **Pause/Resume**, **Check for Updates…**,
**Uninstall OsaGuard…**, and **Quit OsaGuard**. Pausing stops automatic entry
without deleting the saved password.

## Updates

OsaGuard preview updates do not require an Apple Developer account. Update
integrity uses Tauri's separate, persistent minisign-compatible signing key;
Apple Developer ID and notarization concern Gatekeeper and the app's macOS
identity, not that updater signature.

There is one transition for existing users:

- release `v0.1.2-preview.1` (shown inside the app as `0.1.2`) cannot update
  itself and must be replaced manually with `0.1.3-preview.1` from Releases;
- beginning with an installed `0.1.3-preview.1`, later preview versions such as
  `0.1.3-preview.2` are designed to be discovered by OsaGuard.

The bridge build intentionally creates fresh v2 Keychain records, so an
existing preview user enters the administrator password once more. OsaGuard
does not read, modify, or delete the pre-0.1.3 records during migration.

An updater-capable preview checks about 15 seconds after launch and then every
six hours. It considers only newer, published, non-draft OsaGuard prereleases,
loads metadata tied to that exact release tag, and requires a valid updater
signature. When an update is available, OsaGuard shows a system notification
and keeps an install action in the menu if notifications are hidden.

OsaGuard never installs an update silently. You must approve installation. It
downloads and verifies the package first, waits until no administrator dialog
is active, temporarily stops the watcher, installs, and relaunches. A failed
check or invalid signature leaves the running app and watcher in place; you can
always install the newer DMG manually.

Public previews use the same persistent self-signed identity so macOS can keep
their Keychain and Accessibility identity across updates. This continuity is
an explicit preview goal, not Apple trust: `0.1.3-preview.1 →
0.1.3-preview.2` still needs a real release canary before the project claims it
as qualified. Local source builds remain ad-hoc and use a different identity.

## Security warning

Automatic confirmation removes the human action that normally protects an
administrator operation. Once enabled, **any program, script, or malware
already running as your macOS user can cause a matching AppleScript dialog to
appear, and OsaGuard may enter and submit your password.** In security terms,
this can provide passwordless root access to code already running as you.

OsaGuard verifies Apple's authorization process, requires the genuine secure
field, and targets events at that process instead of typing into whichever
window is focused. These checks reduce accidental entry and fake-window
attacks, but they cannot make unattended approval safe against malicious code
in your account.

There is also an unavoidable macOS limitation. Public Accessibility and
CGWindow APIs identify SecurityAgent as the owner of an administrator dialog,
but do not prove which client requested it. OsaGuard can use only short,
best-effort temporal correlation. If another genuine administrator dialog
appears in that matching window, OsaGuard can submit the saved password there.

Do not use OsaGuard on a shared, managed, or otherwise untrusted Mac. Read the
full [security design](docs/SECURITY_DESIGN.md) before enabling automatic mode.

## Uninstall

Use the OsaGuard menu-bar icon and choose **Uninstall OsaGuard…**, directly
above **Quit OsaGuard**. Confirm once. The built-in uninstaller stops the
watcher, disables launch at login, removes only the current v2 Keychain records
that it can verify belong to this installed copy, removes local settings,
resets its Accessibility permission, and moves the app to Trash.

To avoid macOS ownership prompts, the built-in uninstaller intentionally does
not read or delete unversioned records created by preview builds before 0.1.3.
If you used one of those previews and want to remove its leftovers, open
**Keychain Access**, search for the exact names **OsaGuard administrator
password** and **OsaGuard protected product state**, verify that they are old
OsaGuard entries, and delete them manually. This cleanup is optional and macOS
may ask for your login Keychain password.

If you only drag the app to Trash, macOS may retain its Accessibility entry,
settings, and Keychain items. Prefer the built-in uninstaller while the app can
still run. The app bundle can be recovered from Trash, but data removed by the
built-in uninstaller cannot.

## Privacy

OsaGuard has no account, ads, analytics, or cloud password storage. Password
handling and prompt recognition remain on your Mac. See [Privacy](PRIVACY.md).
Report security issues privately as described in [Security policy](SECURITY.md).

## Build from source

This section is for developers. Building requires macOS 13+, Xcode Command Line
Tools, Go 1.23+ with cgo, Rust 1.89, and a current Node.js/npm release supported
by Tauri 2.

```sh
make check
make tray-build
```

The bundle is created under
`app-tauri/src-tauri/target/release/bundle/macos/`. A local ad-hoc build may
have a different Keychain/TCC identity and must not be treated like a public
release. Use test credentials and grant Accessibility only to the exact build
you are testing.

Start contributing with [CONTRIBUTING.md](CONTRIBUTING.md). Technical references
include the [documentation map](docs/README.md), [security design](docs/SECURITY_DESIGN.md),
[qualification record](docs/QUALIFICATION.md), and [release guide](docs/RELEASING.md).

OsaGuard is available under the [MIT License](LICENSE). Third-party components
retain their own licenses; see [Third-party notices](THIRD_PARTY_NOTICES.md).
