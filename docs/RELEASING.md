# Releasing OsaGuard

Public OsaGuard releases use one permanent self-signed macOS Code Signing
certificate plus the separate permanent Tauri updater key. The certificate gives
successive builds a stable designated requirement (DR), which macOS subsystems
such as Keychain can use to recognize updates. It is **not issued or vouched for
by Apple**, does not make OsaGuard an identified developer, and is not a
substitute for notarization.

Apple explicitly warns that a self-signed certificate does not authenticate the
publisher to users or Gatekeeper. OsaGuard retains this distribution model only
to obtain a stable non-Apple code identity without a Developer ID. First launch
therefore remains a manual Finder **right-click → Open** flow.

## One-time repository setup

1. Generate the permanent signing P12 and Tauri updater key once, outside the
   source checkout:

   ```bash
   scripts/bootstrap-release-credentials.sh \
     "$HOME/Library/Application Support/OsaGuard/release-credentials"
   ```

   It creates a fresh mode-0700 directory, uses OpenSSL for a self-signed
   **Code Signing** certificate named `OsaGuard Release Code Signing`, and uses
   the local Tauri CLI for a password-protected updater key. It does **not**
   access, create, unlock, or change the user's login Keychain or Keychain
   search list. Keep the resulting directory backed up and outside every source
   checkout; losing the updater private key ends the existing updater channel.
2. Use `github-public-values.env` from that directory for the two public
   identity values. The certificate fingerprint is public; it is the immutable
   identity pin used by release qualification.
3. Configure the GitHub Actions Environment named `release`. For this
   single-maintainer repository it is restricted to `main`; the separate draft
   and publish workflows require two explicit manual dispatches. A second
   maintainer can later be added as a required reviewer with self-review
   prevention, but a second account is not required to publish OsaGuard.
4. Configure these GitHub Actions **Environment secrets** in `release`:

   - `OSAGUARD_CODE_SIGNING_P12_BASE64`: base64 of the complete P12;
   - `OSAGUARD_CODE_SIGNING_P12_PASSWORD`: the P12 export password;
   - `TAURI_SIGNING_PRIVATE_KEY`;
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.

5. Configure these non-secret **repository variables**:

   - `OSAGUARD_UPDATER_PUBLIC_KEY`: the Tauri public key. It is intentionally
     public and is embedded in every public app build; and
   - `OSAGUARD_CODE_SIGNING_CERTIFICATE_SHA256`: the exact 64-hex-character
     certificate fingerprint.

The ordinary verification job receives only the updater public key. Only the
protected `release` build job receives private signing material. It decodes the
P12 only inside a mode-private temporary directory and imports it into a
temporary Keychain using macOS's non-interactive broad-access mode. That is
deliberately broader than an app-specific ACL, but exists only on the fresh,
isolated GitHub-hosted runner and is deleted with the Keychain; the partition
list still restricts the intended Apple signing-tool path. The job validates the
fixed certificate fingerprint and expiry there and deletes the P12 immediately.
It does not write macOS user, admin, or system Trust Settings. Only after that
validation does it snapshot and extend the runner's Keychain search list. After
a verified restoration, an `always()` cleanup step deletes the temporary
Keychain. If restoration fails, the job deliberately preserves the Keychain and
recovery snapshot instead of destroying the evidence needed to repair the
runner. Commands never print the P12 or password.

The fixed identity name and signing model live in
`scripts/release-signing.json`. Changing the certificate or fingerprint is an
identity migration, not routine maintenance: it breaks the old DR and can make
macOS request Accessibility and Keychain setup again. A self-signed certificate
has no Apple revocation channel, so compromise requires stopping releases,
rotating identity and updater material deliberately, and warning users.

Repository Actions policy should require full-length commit SHAs; every
third-party action in the workflow is pinned to one.

### CI signing-secret boundary

The macOS `security import` CLI has no documented noninteractive stdin or file
descriptor input for an encrypted PKCS#12 passphrase. Its non-GUI mode is
`-P passphrase`, and Apple itself labels that option insecure: the P12 export
password is briefly present in the argument list of the short-lived
`/usr/bin/security` process. It is never printed by the workflow, but process
arguments are not a security boundary against same-user or root code on that
runner.

This workflow therefore has a deliberately narrow trust boundary. Run it only
from protected `main`, by manual dispatch, on a fresh GitHub-hosted macOS
runner. Never run it on a self-hosted, shared, or long-lived runner, from a pull
request, or after introducing unreviewed actions, build steps, dependencies, or
background processes. The release source, locked dependencies, and every
process in the release job are part of the signing-secret TCB; the P12, its
passphrase, and the Tauri updater private key must all be treated as exposed to
that TCB.

The import script keeps P12 files mode-0600 and deletes the P12 immediately
after import. Its broad-access import is acceptable only because the Keychain
is newly created in a fresh GitHub-hosted runner; it must not be reused on a
local, self-hosted, shared, or long-lived machine. It validates the fingerprint,
certificate expiry, and private-key pairing in that disposable Keychain before
it snapshots the runner's user Keychain search list. If restoration fails, it
intentionally preserves both the temporary Keychain and the mode-0600 snapshot,
fails the job, and logs the exact recovery command. Workflow cleanup follows the
same rule: it deletes neither file until it has verified that the original
ordered search list was restored. A stronger future model must use a signing
service or managed key that can import or use the identity without exposing a
P12 passphrase in process arguments.

## Artifact contract

| Asset | Purpose |
|---|---|
| `OsaGuard_*_aarch64.dmg` | Apple Silicon first installation |
| `OsaGuard_*_x64.dmg` | Intel first installation |
| two architecture-specific `.app.tar.gz` files | Tauri updater payloads |
| matching `.app.tar.gz.sig` files | detached Tauri updater signatures |
| `latest.json` | stable updater index with both macOS platform keys |
| `CODE_IDENTITIES.txt` | certificate fingerprint, app DR, and `osaguard-tray` SHA-256, CodeDirectory and CDHash evidence |
| `SHA256SUMS` | post-qualification checksums for every payload asset |

Published tags and assets are immutable. Never replace a published app version
or its `latest.json`; fix a problem by increasing the version.

## Publish a stable release

1. Update the version in all four version-bearing locations checked by
   `scripts/check-release-version.mjs`, add its dated `CHANGELOG.md` section,
   review the RU/EN documentation together, and merge to `main`.
2. Dispatch the **Release** workflow from `main`. An optional version input must
   exactly match repository metadata.
3. The workflow creates a `vX.Y.Z` draft tied to that exact commit, sequentially
   builds Apple Silicon and Intel, and fails closed unless:

   - Go, Rust, frontend, release-tooling and dependency checks pass;
   - the password-protected P12 contains exactly the fixed code-signing identity;
   - its certificate matches `OSAGUARD_CODE_SIGNING_CERTIFICATE_SHA256`;
   - each app has a valid non-ad-hoc signature with hardened runtime;
   - app DRs match exactly across architectures and no DR is pinned to a
     per-build CDHash;
   - `Contents/MacOS` contains only the expected `osaguard-tray` executable of
     the target architecture;
   - updater archive and DMG copies have the same certificate, DR, SHA-256,
     CodeDirectory and CDHash for each architecture;
   - both Tauri updater signatures verify with the permanent updater public key
     and match the exact `latest.json` entries;
   - metadata uses immutable exact-tag asset URLs; and
   - both DMGs contain the qualified app.

4. Only after all gates pass does the workflow attach `SHA256SUMS` and leave the
   exact release as an unpublished draft. It never publishes automatically or
   alters an older stable release.
5. Review the draft's warning, `CODE_IDENTITIES.txt`, `SHA256SUMS`, and assets.
   To intentionally publish it, dispatch **Publish qualified release** from
   `main`, enter its exact `vX.Y.Z` tag, and type `PUBLISH vX.Y.Z`. That separate
   protected workflow re-downloads the exact draft, rechecks its source commit,
   checksums, updater signatures, bundle identities, and architectures before it
   changes `draft=false` and makes the release GitHub's Latest.

If a run fails after draft creation, inspect the failed job and partial draft. A
retry may reuse only the exact unpublished, non-prerelease draft with the same
tag and target commit. The workflow deletes every old draft asset, regenerates
its warning and notes, and builds from scratch. Never delete or replace a
published release to retry it; increment the version instead.

## Installation and Gatekeeper boundary

The self-signed identity makes signatures and DRs stable, but its certificate is
not rooted in Apple trust. The app is not notarized. Gatekeeper can block an
ordinary double-click, so the documented first-install path remains Finder's
context menu **Open**, followed by confirming **Open**. Users are not asked to
install the certificate or add it to system trust settings.

The same certificate and identifier should synthesize the same DR for every
public version. Qualification compares the exact DR across both architectures
and both packaging paths. CDHash and CodeDirectory still change when code or
toolchains change; they are recorded to prove archive/DMG equality, not used as
the cross-version identity. Source and ordinary CI builds remain ad-hoc signed,
do not share the public release identity, and can require separate Accessibility
and Keychain setup.

## First DMG and updater canary

The first public `v0.1.0` release is installed manually from its DMG. It embeds
the permanent Tauri public key and stable endpoint
`releases/latest/download/latest.json`; it cannot update before a higher stable
version exists.

For `v0.1.1`, keep clean `v0.1.0` installations on one Apple Silicon Mac and one
Intel Mac. After publishing `v0.1.1`, verify update notification, tray fallback,
explicit install confirmation, updater signature validation, restart, watcher
recovery inside the app process, and retained Accessibility/Keychain access.
Confirm that both releases'
`CODE_IDENTITIES.txt` files contain the same certificate fingerprint and the
same app DR even though CDHashes differ. Do not re-save the password
before this continuity check. Repeat with notifications denied, offline startup,
a corrupted package and an interrupted installation. Corrupt packages must
never install, and failure must leave the previous app usable.

Primary references:

- [Apple Code Signing Guide: Code Signing Tasks](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
- [Apple TN2206: macOS Code Signing In Depth](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [Tauri updater](https://v2.tauri.app/plugin/updater/)
- [GitHub Actions environments and approvals](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [GitHub Actions configuration variables](https://docs.github.com/en/actions/concepts/workflows-and-actions/variables)
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
