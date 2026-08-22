# Contributing to OsaGuard

Thank you for helping improve OsaGuard. Because the app handles an administrator
password and macOS authorization UI, small changes can have security impact.
Issues and pull requests are welcome in English or Russian.

## Before starting

- Search existing issues and pull requests.
- Open an issue before a large architecture, UX, updater, installer, or security
  change so the approach can be discussed.
- Report vulnerabilities privately through [SECURITY.md](SECURITY.md), not in a
  public issue or pull request.
- Never commit a real password, Keychain export, updater private key, or token.

## Development setup

Development currently requires macOS 13 or later, Xcode Command Line Tools, Go
1.23+, Rust 1.89, and a current Node.js/npm version supported by Tauri 2.

```sh
make check
make tray-build
```

Local app bundles are ad-hoc signed and not notarized. The public binary-release
and publication workflows are deliberately fail-closed until Apple-issued
Developer ID signing, notarization, and stapling are available and qualified.
Do not add a self-signed, locally trusted, or Finder-bypass fallback. Use
throwaway test data. Do not test with a real administrator password unless a
specific local integration test requires it and you understand the cleanup.

## Design rules

- Password bytes must not enter Tauri JavaScript, argv, environment variables,
  logs, the clipboard, policy files, analytics, or network requests.
- Keep Keychain retrieval as late and short-lived as possible. Zero mutable
  secret buffers after use.
- Do not replace PID-targeted event delivery with global keyboard injection.
- Treat Accessibility observations, process metadata, file paths, update data,
  and IPC payloads as untrusted.
- Fail closed when process identity, Apple code signature, secure-field state,
  session state, or updater signature cannot be established.
- Never weaken the warning for unattended administrator confirmation. It is a
  passwordless-root oracle for same-user code, even when all UI checks work.
- Keep the ordinary release-user setup in the app. Terminal-only setup is not a
  substitute for product UX.
- Keep Russian and English strings in sync. Russian is selected for a Russian
  system locale; English is the fallback for every other locale.
- Update the default Russian `README.md` and English `README.en.md` together for
  every user-visible installation, menu, update, or uninstall change.

## Pull requests

Keep changes focused and include:

- what behavior changed and why;
- security-boundary impact;
- tests run and their results;
- screenshots for visible UI changes in both languages;
- documentation or changelog updates when user behavior changes.

Run relevant Go and Rust tests, `go vet`, Clippy with warnings denied, frontend
checks, and packaging checks before requesting review. A pull request template
lists the expected evidence.

By contributing, you agree that your contribution is licensed under the
project's [MIT License](LICENSE).
