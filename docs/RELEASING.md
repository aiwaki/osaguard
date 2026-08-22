# Releasing OsaGuard

## Public-app release gate: closed

OsaGuard's source repository may be public. Its macOS application distribution
is not public yet.

The project currently has no Apple Developer Program membership, Developer ID
Application certificate, or Apple notarization credentials. Until all three
exist and the qualification below has passed, there must be **no** public
OsaGuard DMG, `.app.tar.gz` updater payload, `latest.json`, release draft
advertised as installable, or GitHub “Latest” binary release.

This is a fail-closed product boundary, not a temporary Gatekeeper workaround.
Do not substitute any of the following for Apple-issued distribution identity:

- an ad-hoc signature;
- a self-signed certificate or a locally trusted certificate;
- a Finder right-click → Open instruction;
- a locally generated P12, including the retired bootstrap helper;
- a GitHub Actions Keychain import or a successful `codesign` invocation.

Those techniques may be useful for local development, but do not authenticate
OsaGuard to users or satisfy notarized public distribution. They must never be
used to produce a user-facing release or updater channel.

## What is allowed before Apple distribution credentials exist

- Publish and review source code, documentation, tests, and CI results.
- Build local ad-hoc bundles for controlled development only.
- Exercise updater code only in its local test-build state, where no public
  endpoint or trusted distribution channel is configured.
- Make a clearly labelled source-only tag if needed for development history.
  It must not contain app assets, updater metadata, an installation guide, or a
  claim that it is the latest user release.

The release workflows and retired credential-bootstrap scaffolding in this
repository are not authorization to bypass this gate. Do not dispatch a binary
release workflow while the gate is closed. Do not upload or use signing material
to create a public updater channel for an app that cannot yet be authenticated
and notarized to users.

## Preconditions for opening the gate

Only revisit public app distribution after the project has all of the following:

1. an active Apple Developer Program membership owned or controlled by the
   project maintainer;
2. an Apple-issued **Developer ID Application** certificate and secure handling
   of its private key;
3. notarization credentials (for example, an App Store Connect API key or an
   Apple app-specific password plus the required team data) stored only in a
   protected GitHub Actions environment;
4. a documented, reviewable key-rotation and incident response process for both
   the Developer ID identity and the separate Tauri updater signing key; and
5. clean-machine qualification on Apple Silicon and Intel macOS.

Before enabling a release workflow, remove or permanently disable every
self-signed public-release path and replace it with Developer ID signing,
notarization, and stapling. The GitHub environment must restrict releases to
protected `main`, use only pinned actions, and expose private material only to
the explicitly reviewed release job. Never run release signing on a shared or
self-hosted runner.

## Future release procedure

Once the gate has been opened, the procedure must be updated and then followed
for every public version:

1. Update all version locations, RU/EN user documentation, and `CHANGELOG.md`.
2. Run source, Go, Rust, frontend, dependency, and packaging checks from the
   exact `main` commit being released.
3. Build Apple Silicon and Intel bundles with the Apple-issued Developer ID
   identity and hardened runtime. Verify the bundle identifier, executable
   layout, architecture, designated requirement, and signature on the resulting
   app and DMG.
4. Submit the exact distributable to Apple notarization, wait for acceptance,
   staple the resulting ticket, and verify stapling. A successful signature is
   not a notarization result.
5. Create the Tauri updater archives and detached signatures with the permanent
   updater key. Generate immutable `latest.json` entries that refer only to the
   exact release assets. Keep the updater code disabled unless its embedded
   public key and endpoint correspond to this authenticated channel.
6. In a draft release, verify checksums, updater signatures, Developer ID
   identity, notarization/stapling, version, architectures, and the app inside
   each DMG. Record reproducible evidence; a draft is not a user release.
7. Test a first installation on clean Apple Silicon and Intel machines. Then
   test an N → N+1 canary: notification, tray fallback, explicit confirmation,
   offline behaviour, corrupted payload rejection, failed-install watcher
   recovery, restart, Accessibility continuity, and retrieval of the existing
   Keychain item before re-saving a password.
8. Publish only after a maintainer explicitly reviews the draft evidence. Never
   replace a published app asset or updater manifest; issue a higher version.

The source-level updater implementation does not prove that any of these steps
have happened. Its design is documented in the code and user READMEs, but no
public updater channel exists at this time.

## References

- [Apple: Signing macOS software](https://developer.apple.com/developer-id/)
- [Apple: Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
- [Tauri updater](https://v2.tauri.app/plugin/updater/)
- [GitHub Actions: environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
