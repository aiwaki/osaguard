# Preview signing identities

OsaGuard preview releases use two independent, persistent identities:

- `osaguard-preview-code-signing.pem` is the public half of the self-signed
  macOS Code Signing identity used to keep the app's designated requirement
  stable between preview builds. Its certificate SHA-256 fingerprint is
  `A6:CF:1F:0B:C8:28:D9:3E:7B:4F:0F:BC:87:A5:16:39:68:AC:D7:49:9D:EC:BF:B2:93:14:EC:D7:6D:B9:2C:52`.
- [`../../config/osaguard-preview-updater.pub`](../../config/osaguard-preview-updater.pub)
  is the Tauri/minisign public key embedded only into release builds. Its
  minisign key ID is `45A1C751263EEA3C`.

Neither public key is secret. Their private halves exist only in protected
GitHub Actions secrets. Replacing either identity is a manual migration:
changing the macOS certificate breaks Keychain and Accessibility continuity,
while changing the updater key prevents installed builds from accepting later
packages.

The self-signed certificate provides continuity, not Apple trust. Preview apps
remain outside Developer ID and are not notarized.
