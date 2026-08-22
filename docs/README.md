# OsaGuard documentation

The root README files are the user entry point. Keep them short enough for a
first-time Mac user and update English and Russian together whenever install,
menu, update, uninstall, language, privacy, or security-warning behavior changes.

| Document | Purpose |
|---|---|
| [Security design](SECURITY_DESIGN.md) | Trust boundaries, password handling, prompt recognition, and the unavoidable same-user risk. |
| [Qualification](QUALIFICATION.md) | Evidence already collected and live gates that remain external. |
| [Releasing](RELEASING.md) | Public preview procedure and the separately closed stable channel. |

OsaGuard has a manual Apple-Silicon preview channel. Preview builds are ad-hoc
signed, are not notarized, and do not currently have automatic updates. The
stable channel remains fail-closed until Developer ID signing, notarization, and
stapling can be qualified.
