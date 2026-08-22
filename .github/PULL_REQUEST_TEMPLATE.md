## Summary

What changed, and what user or developer problem does it solve?

## Security impact

Describe any effect on password bytes, Keychain access, Accessibility, process
identity, targeted input, installation privileges, updater trust, launch agents,
or the automatic-confirmation warning. Write “none” only after considering each
boundary.

## Verification

List exact commands and results. Include relevant Go tests, Rust tests, `go vet`,
Clippy with warnings denied, frontend checks, and packaging checks.

## UI and documentation

For visible changes, attach sanitized screenshots in English and Russian. Explain
any localization, onboarding, README, privacy, or changelog changes.

## Checklist

- [ ] The change is focused and contains no unrelated generated files.
- [ ] No credential, Keychain export, signing secret, updater private key, token,
      or personal authentication screenshot is included.
- [ ] Password bytes do not enter JavaScript, argv, environment variables, logs,
      the clipboard, policy files, analytics, or network requests.
- [ ] Failure of a security or identity check remains fail-closed.
- [ ] Russian and English user-facing text remain consistent.
- [ ] Tests and documentation were updated where behavior changed.
