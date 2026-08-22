# Changelog

All notable changes to OsaGuard will be documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases
will follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-13

### Added

- in-process native macOS bridge for recognizing supported AppleScript
  administrator dialogs and sending input to a verified Apple authorization
  process.
- local Keychain password storage and deletion support.
- menu-bar application prototype and launch-at-login integration.
- exact-rule developer tooling and security qualification tests.
- beginner documentation in English and Russian.
- stable GitHub release automation for Apple Silicon and Intel, with mandatory
  Tauri updater signatures and immutable update metadata.
- a release identity manifest recording the `osaguard-tray` app executable's
  CodeDirectory, CDHash, and SHA-256 for both architectures.

### Changed

- public UX uses a guided setup window, direct tray actions, system-language
  selection, a native secure password prompt, and an explicit security warning.

### Security

- automatic confirmation is documented as a passwordless-root oracle for code
  already running in the configured user account.
- password input is kept outside Tauri JavaScript, command arguments, environment
  variables, logs, and the clipboard.

Public DMGs use OsaGuard's permanent self-signed code-signing certificate and
are not notarized by Apple. The first installed release is manual (Finder
right-click → Open); later stable releases use the separately signed Tauri
updater channel.

[Unreleased]: https://github.com/aiwaki/osaguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/aiwaki/osaguard/releases/tag/v0.1.0
