# OsaGuard documentation

The root README files are the user entry point. Keep them short enough for a
first-time Mac user and update English and Russian together whenever install,
menu, update, uninstall, language, privacy, or security-warning behavior changes.

| Document | Purpose |
|---|---|
| [Security design](SECURITY_DESIGN.md) | Trust boundaries, password handling, prompt recognition, and the unavoidable same-user risk. |
| [Qualification](QUALIFICATION.md) | Evidence already collected and live gates that remain external. |
| [Releasing](RELEASING.md) | Public-app release gate and the future Developer ID/notarization procedure. |

There is no public OsaGuard app release or updater channel today. Source builds
remain ad-hoc signed; the binary-release workflows are intentionally fail-closed
until Apple-issued Developer ID signing, notarization, and stapling can be
properly qualified.
