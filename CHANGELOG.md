# Changelog

All notable changes to OsaGuard will be documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases
will follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-22

### Added

- in-process native macOS bridge for recognizing supported AppleScript
  administrator dialogs and sending input to a verified Apple authorization
  process.
- local Keychain password storage and deletion support.
- menu-bar application prototype and launch-at-login integration.
- exact-rule developer tooling and security qualification tests.
- beginner documentation in English and Russian.
- fail-closed GitHub workflows that prevent binary release creation and
  publication until Apple-issued Developer ID signing, notarization, and
  stapling can be qualified.
- source-level Tauri updater implementation and release documentation, kept
  disabled until a real authenticated public channel exists.

### Changed

- public UX uses a guided setup window, direct tray actions, system-language
  selection, a native secure password prompt, and an explicit security warning.

### Security

- automatic confirmation is documented as a passwordless-root oracle for code
  already running in the configured user account.
- password input is kept outside Tauri JavaScript, command arguments, environment
  variables, logs, and the clipboard.
- the earlier self-signed-P12 release experiment is retired. No binary release
  workflow can access it, and no public DMG or updater channel exists.

[Unreleased]: https://github.com/aiwaki/osaguard/commits/main
[0.1.0]: https://github.com/aiwaki/osaguard/tree/main
