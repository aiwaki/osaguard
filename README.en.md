# OsaGuard

<div align="center">

<img src="app-tauri/icon.png" width="128" height="128" alt="OsaGuard app icon">

[Русский](README.md) · **English**

[![macOS 13+](https://img.shields.io/badge/macOS-13%2B-000000?logo=apple)](#distribution-status)
[![CI](https://github.com/aiwaki/osaguard/actions/workflows/ci.yml/badge.svg)](https://github.com/aiwaki/osaguard/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

OsaGuard is an experimental macOS menu-bar app. After explicit setup, it can
recognize a supported system administrator-password dialog created through
AppleScript and enter and submit a saved password.

## Distribution status

OsaGuard is released as a **Preview** through [GitHub Releases](https://github.com/aiwaki/osaguard/releases).
The current corrected build, `v0.1.1-preview.1`, is for Apple Silicon and macOS 13+. It is
a manual preview installation, not the stable channel.

The project has no Apple Developer Program membership, Developer ID identity, or
Apple notarization ticket. The preview is therefore ad-hoc signed, not notarized,
and does not promise that Accessibility permission or Keychain access will carry
across versions. The built-in updater is deliberately off for previews;
download later previews manually from Releases.

### Installing the preview

1. Open the newest [**Pre-release**](https://github.com/aiwaki/osaguard/releases).
2. Download `OsaGuard_0.1.1_preview.1_aarch64.dmg` and move the app to
   Applications.
3. Run OsaGuard only from Applications. If macOS warns about the unnotarized
   preview, do not disable Gatekeeper globally: use Finder's contextual **Open**
   only for this exact preview if you trust it.

Do not install OsaGuard files from outside the project release page. A preview
does not promise stability or compatibility with future stable releases.

## Read this before running OsaGuard

OsaGuard's automatic confirmation removes the human action that normally
protects an administrator operation. Once enabled, **any program, script, or
malware already running in your macOS account can cause a matching AppleScript
dialog to appear, and OsaGuard may enter and submit your password.** In security
terms, this can act as a passwordless-root oracle for code running as you.

OsaGuard verifies the Apple authorization process and targets keyboard events at
that process instead of the globally focused window. Those checks reduce
accidental typing and fake-window attacks, but they cannot make unattended
approval safe against malicious code already running in your account.

There is also an unavoidable causality limit: macOS's public Accessibility and
CGWindow APIs identify SecurityAgent as the owner of an administrator dialog,
but do not identify or cryptographically bind that dialog to the client that
requested authorization. OsaGuard can therefore use only short, best-effort
temporal correlation. If a different genuine SecurityAgent administrator dialog
appears in the same short matching window, OsaGuard can submit the saved
password to that dialog instead.

Do not use OsaGuard on a shared, managed, or otherwise untrusted Mac. Read
[Security design](docs/SECURITY_DESIGN.md) first.

## What OsaGuard is for

OsaGuard is intended for the standard administrator-password dialog created by
`/usr/bin/osascript`, usually from AppleScript's `with administrator privileges`.
It is not tied to one application and is not an operation allowlist.

It does **not** fill:

- the Mac login or lock screen;
- FileVault, website, browser, or application passwords;
- arbitrary password fields;
- every macOS authentication dialog.

## Testing from source

This is a developer section, not ordinary installation instructions. You need
macOS 13+, Xcode Command Line Tools, Go 1.23+ with cgo, Rust 1.89, and a current
Node.js/npm release supported by Tauri 2.

```sh
make check
make tray-build
```

The local bundle is created under
`app-tauri/src-tauri/target/release/bundle/macos/`. It is ad-hoc signed, not
notarized, has no stable update channel, and may acquire a new TCC identity on
each rebuild. Install it only for controlled development; do not save a real
administrator password in it without understanding the risk and cleanup
consequences above.

For such local testing, place the app in Applications and grant Accessibility
only to that exact build in **System Settings → Privacy & Security →
Accessibility**. If the old OsaGuard row does not grant the rebuilt app access,
remove the stale row, then request and enable access again.

## Setup and menu

When a preview or local development build is running, the app explains three one-time
steps:

1. grant Accessibility to that exact build;
2. save the password in a native secure macOS dialog;
3. explicitly accept the automatic-confirmation warning.

The password stays in the native bridge and Keychain: it is not passed to the
Tauri WebView, command arguments, environment variables, logs, or clipboard.
Canceling the password dialog is a silent normal action and leaves the existing
password unchanged.

The menu-bar menu contains status, **Open OsaGuard…**, **Save administrator
password…** or **Change saved password…**, **Pause/Resume**, **Check for
Updates…**, **Uninstall OsaGuard…**, and **Quit OsaGuard**. Pausing stops
automatic entry without deleting the password. Uninstall stops the watcher,
disables login startup, removes verified OsaGuard Keychain items and local
settings, resets the OsaGuard Accessibility permission, and moves the app to
Trash.

The interface uses Russian for a Russian macOS system language and English for
all other system languages.

## Updates

The source contains a Tauri updater implementation: it checks 15 seconds after
launch and then every six hours, uses native notifications, and asks for an
explicit installation confirmation. The public preview is **not connected
to an updater channel**: GitHub's `latest` endpoint does not identify prereleases
and would be an unreliable source.

The preview therefore reports “Updates unavailable in this preview build.” This
is expected fail-closed behavior. Install the next preview manually from
Releases; a dedicated signed preview appcast will be added only after a real
one-preview-to-the-next qualification.

## Privacy

OsaGuard has no account, ads, analytics, cloud password storage, or clipboard
integration. Password handling and prompt recognition happen locally. See
[Privacy](PRIVACY.md) for details and [Security policy](SECURITY.md) for private
vulnerability reporting.

## Contributing

Start with [Contributing](CONTRIBUTING.md). Technical references are the
[documentation map](docs/README.md), [security architecture](docs/SECURITY_DESIGN.md),
[qualification record](docs/QUALIFICATION.md), and
[release gate](docs/RELEASING.md).

OsaGuard is available under the [MIT License](LICENSE). Third-party components
retain their own licenses; see [Third-party notices](THIRD_PARTY_NOTICES.md).
