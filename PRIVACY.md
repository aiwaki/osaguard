# Privacy

Last updated: 2026-08-13

OsaGuard is designed as a local macOS utility. It does not require an OsaGuard
account or cloud service.

## Data handled on your Mac

OsaGuard handles the following local data:

- **Administrator password.** You enter it in a native macOS secure field. It is
  stored as an item in your login Keychain and retrieved only when OsaGuard is
  about to handle an eligible Apple authorization prompt. OsaGuard does not
  intentionally write the plaintext password to files, logs, command arguments,
  environment variables, or the clipboard.
- **Settings and status.** OsaGuard may store preferences such as whether it
  starts at login, whether automatic handling is paused, and whether onboarding
  is complete.
- **Local operational information.** The app may keep non-secret diagnostic
  information needed to explain setup or failures. It must not include the
  password or password-field contents.

OsaGuard cannot display or export the password saved in Keychain. Replacing the
password overwrites the prior item; forgetting it deletes the OsaGuard Keychain
item.

## Permissions

OsaGuard requests macOS Accessibility permission so it can inspect a supported
Apple authorization dialog and send keyboard events directly to the verified
Apple process. The permission is not used to collect general typing or browsing
history. macOS controls this permission, and you can revoke it at any time in
System Settings.

OsaGuard may also register itself to start when you log in. You can disable that
behavior from OsaGuard or macOS Login Items settings.

## Network activity

OsaGuard does not include analytics, advertising, telemetry, cloud password
storage, or cloud synchronization.

The first public preview does not contact GitHub for updates: its updater is
disabled and later previews are installed manually. A future signed updater
channel would contact GitHub Releases to check metadata and, only after your
approval, download a package. GitHub may then receive normal connection
information such as your IP address and user agent; GitHub's own privacy terms
apply.

OsaGuard itself does not upload prompts, passwords, application lists, or usage
history.

## Retention and deletion

Local settings remain until you reset or uninstall OsaGuard. The stored password
remains in Keychain until you choose **Remove stored password** or delete the
OsaGuard Keychain item. Revoking Accessibility stops access to authorization UI
but does not by itself delete the Keychain item.

For a complete uninstall, choose **Uninstall OsaGuard…** in the menu and confirm.
OsaGuard stops its watcher, disables launch at login, deletes its Keychain item
and local settings, resets its Accessibility permission, and moves the app to
the Trash. The app remains recoverable until the Trash is emptied, but its
deleted secret and settings are not restored with it.

## Changes and questions

Material changes will be documented in this file and the project changelog. For
a security-sensitive privacy issue, use the private process in
[SECURITY.md](SECURITY.md). For a general question, open a GitHub issue without
including passwords, authentication screenshots, or other secrets.
