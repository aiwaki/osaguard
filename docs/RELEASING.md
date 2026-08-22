# Releasing OsaGuard

## Public preview channel

OsaGuard may be published as an explicitly labelled **GitHub prerelease** without
an Apple Developer membership. This matches the project's Slipstream preview
model, not a stable macOS distribution channel.

The current preview is `v0.1.2-preview.1`:

- Apple Silicon and macOS 13+ only;
- built on a disposable GitHub-hosted `macos-14` runner;
- ad-hoc signed with Tauri's `signingIdentity: "-"` — no P12, Keychain import,
  Developer ID identity, or local maintainer Mac is involved;
- distributed only as a manual-install DMG and ZIP with `SHA256SUMS` and GitHub
  Actions provenance;
- marked `prerelease: true` and `make_latest: false`;
- not notarized, not a stable release, and not an identity-continuity promise
  for Accessibility or Keychain items;
- updater-disabled. GitHub's `releases/latest` does not identify prereleases,
  so it is not an acceptable preview update endpoint.

The public README and release notes must state all of those boundaries, include
the passwordless-root warning, and tell users not to disable Gatekeeper globally.
Finder's contextual **Open** is an installation decision for a specific trusted
preview, not a general trust workaround.

### Preview publication procedure

1. Update the README files, changelog, security notes, and authorized preview
   sequence. Every correction uses a new sequence; published assets are never
   replaced.
2. Push `main`; wait for the exact successful `ci.yml` run.
3. Manually dispatch **Publish macOS preview** from `main` with the exact
   authorized sequence (`1` for the current source). It must reject every other
   sequence or ref and an absent or mismatched CI result.
4. The GitHub-hosted runner builds the same immutable source, creates a draft,
   uploads exactly the DMG, ZIP, and checksum manifest, validates their names
   and the release commit, attests the artifacts, and publishes that exact draft
   as a prerelease.
5. Verify the public release page, SHA-256 manifest, source commit, architecture,
   and prerelease flag. Never replace a published preview asset; use a new
   preview sequence instead.

No preview workflow may access `secrets.*`, import a certificate, modify a
Keychain search list, or use a self-signed P12. Do not run preview signing on a
self-hosted runner.

## Stable channel: closed

The stable binary channel remains closed until the project deliberately has all
of the following:

1. an active Apple Developer Program membership owned by the maintainer;
2. an Apple-issued **Developer ID Application** certificate and safe private-key
   custody;
3. notarization credentials and a successful submission plus stapling;
4. a reviewed updater key, an authenticated stable appcast, and an `N → N+1`
   test covering notification, explicit install confirmation, failed-update
   recovery, Accessibility, and saved-password continuity;
5. clean-machine qualification on Apple Silicon and Intel macOS.

Until then, `.github/workflows/release.yml` and
`.github/workflows/publish-release.yml` intentionally fail. A preview must never
be reclassified as stable or Latest merely because its ad-hoc signature verifies
on the build runner.

## References

- [Tauri macOS signing](https://v2.tauri.app/distribute/sign/macos/)
- [Tauri updater](https://v2.tauri.app/plugin/updater/)
- [GitHub Actions attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations)
