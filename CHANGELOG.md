# Changelog

All notable changes to OsaGuard will be documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases
will follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2-preview.1] - 2026-08-23

### Fixed

- the installed copy now relaunches only after the DMG process releases the
  single-instance lock.
- in-place replacement keeps rollback available and moves the previous app to
  the Trash only after the delayed relaunch has been scheduled.
- a DMG copy now says whether it will install, update, or open the already
  installed app; older DMGs never offer to replace a newer installed version.

## [0.1.1-preview.1] - 2026-08-23

Withdrawn after local release-artifact qualification found a relaunch race.

### Fixed

- packaged dashboard startup now grants only the Tauri event permissions it
  uses and no longer remains on the loading screen when initialization fails.
- startup failures now render a visible recovery action instead of leaving a
  permanent spinner.

### Security

- the corrected preview remains an Apple-Silicon-only, ad-hoc, unnotarized
  prerelease with manual updates; the stable channel remains closed.

## [0.1.0-preview.1] - 2026-08-22

### Added

- public Apple-Silicon GitHub Preview with an ad-hoc DMG, ZIP alternative,
  SHA-256 checksums, and GitHub Actions provenance.
- a hosted-only preview publication workflow that creates an explicit
  prerelease and never marks it as Latest.

### Security

- preview distribution does not import a signing certificate, touch a Keychain,
  or configure an updater endpoint. Installation and later preview updates are
  manual.

## [0.1.0] - 2026-08-22

### Added

- in-process native macOS bridge for recognizing supported AppleScript
  administrator dialogs and sending input to a verified Apple authorization
  process.
- local Keychain password storage and deletion support.
- menu-bar application prototype and launch-at-login integration.
- exact-rule developer tooling and security qualification tests.
- beginner documentation in English and Russian.
- a fail-closed stable GitHub release workflow pending Apple-issued Developer ID
  signing, notarization, and stapling.
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
- the earlier self-signed-P12 release experiment is retired. No public workflow
  can access it; previews use GitHub-hosted ad-hoc bundles only.

[Unreleased]: https://github.com/aiwaki/osaguard/commits/main
[0.1.2-preview.1]: https://github.com/aiwaki/osaguard/releases/tag/v0.1.2-preview.1
[0.1.1-preview.1]: https://github.com/aiwaki/osaguard/releases/tag/v0.1.1-preview.1
[0.1.0-preview.1]: https://github.com/aiwaki/osaguard/releases/tag/v0.1.0-preview.1
[0.1.0]: https://github.com/aiwaki/osaguard/tree/main
