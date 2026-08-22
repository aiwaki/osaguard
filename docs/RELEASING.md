# Releasing OsaGuard

## Public preview channel

OsaGuard may be published as an explicitly labelled **GitHub prerelease** without
an Apple Developer membership. This matches the project's Slipstream preview
model, not a stable macOS distribution channel.

`v0.1.3-preview.1` is the first updater-capable bridge preview:

- Apple Silicon and macOS 13+ only;
- built on a disposable GitHub-hosted `macos-14` runner;
- signed with one persistent self-signed Code Signing identity imported into a
  disposable runner Keychain; it is not an Apple Developer ID certificate and
  gives no Gatekeeper or notarization trust;
- bound to a persistent, separate Tauri/minisign updater key. The public key is
  embedded in the app while the private key is available only to the release
  workflow;
- distributed as a DMG and ZIP plus an updater archive, detached signature,
  immutable exact-tag `latest.json`, `SHA256SUMS`, and GitHub Actions provenance;
- marked `prerelease: true` and `make_latest: false`;
- not notarized and not a stable release;
- discovered through a bounded GitHub prerelease query. Tauri then checks only
  the selected release's immutable exact-tag `latest.json` and verifies the
  downloaded archive with the embedded updater public key.

The installed `0.1.2` reports stable SemVer and therefore ranks above every
`0.1.2-preview.N`. It must be replaced manually by `0.1.3-preview.1`. From that
bridge onward, package versions and tags are canonical and identical, such as
`0.1.3-preview.2` and `v0.1.3-preview.2`.

The public README and release notes must state all of those boundaries, include
the passwordless-root warning, and tell users not to disable Gatekeeper globally.
Finder's contextual **Open** is an installation decision for a specific trusted
preview, not a general trust workaround.

### Preview publication procedure

1. Update the README files, changelog, security notes, package version, and
   authorized preview sequence. Every correction uses a new canonical preview
   version; published assets are never replaced.
2. Push `main`; wait for the exact successful `ci.yml` run.
3. Manually dispatch **Publish macOS preview** from `main` with the exact
   authorized sequence (`1` for the current source). It must reject every other
   sequence or ref and an absent or mismatched CI result.
4. The GitHub-hosted runner imports the persistent self-signed identity into a
   new temporary Keychain, configures the public updater key, builds and signs
   the app, and checks that the app satisfies the exact bundle identifier plus
   signing-certificate requirement. It deletes the temporary Keychain even on
   failure.
5. The runner verifies the updater signature offline, creates immutable
   exact-tag metadata, attests the exact DMG, ZIP, updater archive, signature,
   appcast, and checksum manifest, then creates and uploads the validated draft.
6. Inspect the draft and its assets, then publish it manually as a prerelease
   with **Set as latest release** disabled. Verify the public release page,
   SHA-256 manifest, source commit, architecture, prerelease flag, updater
   signature. The first bridge (`preview.1`) cannot prove an updater transition;
   leave that canary explicitly pending. Before treating the channel as
   qualified, verify the first real `preview.1 → preview.2` transition. Never
   replace a published preview asset; use a new preview sequence instead.

Required repository configuration:

- secrets `APPLE_CERTIFICATE` and `APPLE_CERTIFICATE_PASSWORD` for the
  persistent self-signed P12. Its certificate must exactly match
  `docs/release-signing/osaguard-preview-code-signing.pem`; the public identity
  name is fixed as `OsaGuard Preview Code Signing`;
- secrets `TAURI_SIGNING_PRIVATE_KEY` and
  `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` for updater artifacts;
- the corresponding committed updater public key at
  `config/osaguard-preview-updater.pub`.

These identities must remain constant across preview updates. Rotating either
one is a manual migration and must not be presented as a transparent update.
Do not run preview signing on a self-hosted runner.

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
be reclassified as stable or Latest merely because its self-signed code
signature verifies on the build runner.

## References

- [Tauri macOS signing](https://v2.tauri.app/distribute/sign/macos/)
- [Tauri updater](https://v2.tauri.app/plugin/updater/)
- [GitHub Actions attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations)
