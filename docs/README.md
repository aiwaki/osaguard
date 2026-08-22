# OsaGuard documentation

The root README files are the user entry point. Keep them short enough for a
first-time Mac user and update English and Russian together whenever install,
menu, update, uninstall, language, privacy, or security-warning behavior changes.

| Document | Purpose |
|---|---|
| [Security design](SECURITY_DESIGN.md) | Trust boundaries, password handling, prompt recognition, and the unavoidable same-user risk. |
| [Qualification](QUALIFICATION.md) | Evidence already collected and live gates that remain external. |
| [Releasing](RELEASING.md) | Public preview procedure and the separately closed stable channel. |

OsaGuard has an Apple-Silicon preview channel. Public previews use a persistent
self-signed macOS identity and a separate signed Tauri updater channel, but are
not Developer ID signed or notarized. `0.1.3-preview.1` is the one-time manual
bridge; later previews can update only after explicit user confirmation. The
stable channel remains fail-closed until Developer ID signing, notarization,
and stapling can be qualified.
