# OsaGuard

<div align="center">

<img src="app-tauri/icon.png" width="128" height="128" alt="OsaGuard app icon">

[Русский](README.md) · **English**

[![macOS 13+](https://img.shields.io/badge/macOS-13%2B-000000?logo=apple)](#installation)
[![CI](https://github.com/aiwaki/osaguard/actions/workflows/ci.yml/badge.svg)](https://github.com/aiwaki/osaguard/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

OsaGuard is a macOS menu-bar app that can enter and submit your administrator
password when AppleScript shows the standard macOS administrator dialog.

## Read this before using OsaGuard

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
[Security design](docs/SECURITY_DESIGN.md) before deciding.

## What OsaGuard is for

OsaGuard handles the standard administrator-password dialog created by
`/usr/bin/osascript`, usually from AppleScript's `with administrator privileges`.
It is intended for repeated operations that cannot be changed to use a safer,
narrowly privileged mechanism.

It does **not** fill:

- the Mac login or lock screen;
- FileVault, website, browser, or application passwords;
- arbitrary password fields;
- every macOS authentication dialog.

## Installation

The public release is designed so ordinary users do not need Terminal.

1. Download the DMG for your Mac from the
   [latest release](https://github.com/aiwaki/osaguard/releases/latest). The
   file containing `aarch64` is for Apple Silicon; `x64` is for Intel.
2. Open the disk image and drag **OsaGuard** into **Applications**. Public builds
   use OsaGuard's permanent self-signed certificate; it is not issued by Apple,
   and the app **is not notarized by Apple**. If macOS blocks the normal launch,
   right-click OsaGuard in Applications, choose **Open**, then confirm **Open**
   once more.
3. Open OsaGuard from Applications. It lives in the menu bar instead of the Dock.
4. Complete the one-time setup shown by OsaGuard.

### One-time setup

OsaGuard explains each step and shows whether it is complete:

1. **Allow Accessibility.** The installed Tauri app itself makes the native macOS
   permission request. macOS requires you to approve OsaGuard once in **System
   Settings → Privacy & Security → Accessibility**; an app cannot safely grant
   this permission to itself. On the first click, use the native macOS prompt to
   continue to System Settings. If access is still missing afterward, OsaGuard
   shows a separate **Open Accessibility settings** button.
2. **Store password in Keychain.** OsaGuard opens a native macOS secure-password
   window. The password remains inside OsaGuard's in-process native Go bridge
   and is stored in your login Keychain. It never passes through the Tauri web
   interface, command arguments, environment variables, logs, the clipboard, or
   the Rust/Go ABI. OsaGuard cannot display or export the saved password; it can
   only replace or delete it.
3. **Accept the automatic-confirmation warning.** OsaGuard remains inactive
   until you explicitly accept the security warning above. Choosing **Not now**
   leaves setup incomplete and no password is entered.

After setup, the Tauri app starts at login and watches locally. Cargo builds the
Go bridge as a C archive and links it into `osaguard-tray`; the watcher runs on a
worker thread inside that one app process. The production bundle's
`Contents/MacOS` contains only `osaguard-tray`, and there is no separate watcher
login item. OsaGuard removes the obsolete watcher LaunchAgent used by earlier
development builds. Normal use does not require
repeated password entry or a Terminal window. Public updates keep the same
certificate and designated requirement so macOS can track the release identity
across versions. Certificate rotation or replacement with a local build
requires Accessibility and password setup again.

## Menu-bar controls

The menu is intentionally action-oriented, without ambiguous checkmarks:

- a read-only status such as **On**, **Paused**, or **Setup required**;
- **Open OsaGuard…** for setup, security explanation, and preferences;
- **Save administrator password…** or **Change saved password…**, which opens
  the native secure window directly instead of opening the dashboard;
- **Pause** or **Resume**;
- **Check for Updates…**;
- **Uninstall OsaGuard…**;
- **Quit OsaGuard**.

Pausing stops automatic submission without deleting the Keychain item. Quitting
stops the app and its in-process watcher until OsaGuard is opened again. Canceling the
native password window is a normal no-op: OsaGuard shows no error and preserves
the previously stored password.

## Languages

OsaGuard follows the macOS system language:

- Russian system language → Russian interface;
- every other system language → English interface.

Russian and English are supported.

## Updates

Public builds use the standard Tauri updater and native macOS notifications.
OsaGuard checks 15 seconds after launch and every six hours. When a version is
available, it sends one RU/EN Notification Center notification and keeps an
**Install OsaGuard VERSION…** fallback in the menu in case notifications are
disabled. Installation always requires confirmation.

The package is downloaded and its mandatory Tauri signature is verified while
the in-process watcher keeps running. OsaGuard stops that watcher only
immediately before installation, then restarts the app; a failed installation
restores it. The newest DMG on Releases remains the manual recovery path; the
same Gatekeeper steps as the first installation apply.

The current local test build has no updater endpoint or public key, so its
update action reports that updates are unavailable in a test build. The first
stable public release, `v0.1.0`, must be installed manually from its DMG. It
already contains the permanent public key and stable update channel, so the
next stable release can be installed through OsaGuard. Every updater package is
verified independently of the app's self-signed code signature. See [Releasing
OsaGuard](docs/RELEASING.md).

## Privacy

OsaGuard has no account, ads, analytics, cloud password storage, or clipboard
integration. Password handling and prompt recognition happen locally. The
official build contacts GitHub only to check for and download updates.

See [Privacy](PRIVACY.md) for the complete data-handling statement and
[Security policy](SECURITY.md) for private vulnerability reporting.

## Troubleshooting

### Accessibility is listed or enabled, but setup remains on step one

Wait a few seconds: OsaGuard checks the permission automatically. If the step
does not complete, select the existing OsaGuard row in **System Settings →
Privacy & Security → Accessibility** and remove it with the **−** button. Return
to OsaGuard and choose **Request access** again, then approve the newly added
entry. Every local ad-hoc rebuild can have a new TCC code identity, even if the
path and bundle identifier look unchanged, so an old enabled switch does not
grant access to the rebuilt app. Always grant permission only after the exact
build is installed in Applications. Public OsaGuard releases instead use one
permanent self-signed certificate and a stable designated requirement. A normal
same-certificate update should retain that identity; certificate rotation or a
local replacement requires this reset.

### The password is not entered

Open OsaGuard and check the status. Confirm that:

- setup is complete and OsaGuard is not paused;
- Accessibility is still enabled;
- the password has been stored in Keychain;
- the Mac is unlocked;
- the dialog came from AppleScript and its password field is empty.

OsaGuard deliberately ignores unsupported or ambiguous dialogs.

### I changed my administrator password

Choose **Change saved password…** in the OsaGuard menu and enter the new password
in the native secure window. Canceling keeps the old Keychain value unchanged.
OsaGuard cannot recover or show that value.

### An update failed

Quit OsaGuard, download the newest DMG from Releases, and replace the copy in
Applications. If macOS blocks it, use right-click → **Open**. You may then need
to grant Accessibility and save the password again only if the certificate or
designated requirement no longer matches the installed public release.

## Uninstall

Choose **Uninstall OsaGuard…** in the menu and confirm the action.
OsaGuard stops its in-process watcher, disables login startup, removes every verified password
item it saved in Keychain and local settings, resets its Accessibility permission, and moves the app to
the Trash, where it remains recoverable until the Trash is emptied. **Quit
OsaGuard** remains available when you only want to stop it.
The production bundle contains only the app executable and has no separate
watcher login item.

## Build from source

Source builds are for developers. They are ad-hoc signed and not notarized, and
do not share the permanent self-signed identity of public releases. The official
workflow imports the protected release P12, builds both architectures, signs
every updater package with the separate permanent Tauri key, and qualifies the
certificate fingerprint and designated requirements before publication. Each
local rebuild can change the identity macOS TCC associates with the app: remove
the previous OsaGuard Accessibility row and grant the newly installed build
access again. Local source builds intentionally have no configured update
channel.

Requirements:

- macOS 13 or later;
- Xcode Command Line Tools;
- Go 1.23 or later with cgo;
- Rust 1.89;
- a current Node.js and npm release supported by Tauri 2.

Run the checks and build the local app:

```sh
make check
make tray-build
```

The local app bundle is created under
`app-tauri/src-tauri/target/release/bundle/macos/`. Current command-line and
exact-rule tooling is intended for development and security qualification; see
the command help and [Security design](docs/SECURITY_DESIGN.md) before using it.

If an older development CLI build saved a password with an arbitrary
`--account`, run `osaguard forget-password` from that **same** binary before
discarding it. The public app intentionally refuses to delete a Keychain item
whose ACL identifies another executable, because that deletion cannot be
verified safely.

## Contributing

Contributions are welcome. Start with [Contributing](CONTRIBUTING.md), follow the
[Code of Conduct](CODE_OF_CONDUCT.md), and report security issues privately as
described in [Security policy](SECURITY.md).

Developer references: [documentation map](docs/README.md),
[security architecture](docs/SECURITY_DESIGN.md),
[qualification record](docs/QUALIFICATION.md), and
[release procedure](docs/RELEASING.md).

OsaGuard is available under the [MIT License](LICENSE). Third-party components
retain their own licenses; see [Third-party notices](THIRD_PARTY_NOTICES.md).
