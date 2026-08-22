# OsaGuard documentation

The root README files are the user entry point. Keep them short enough for a
first-time Mac user and update English and Russian together whenever install,
menu, update, uninstall, language, privacy, or security-warning behavior changes.

| Document | Purpose |
|---|---|
| [Security design](SECURITY_DESIGN.md) | Trust boundaries, password handling, prompt recognition, and the unavoidable same-user risk. |
| [Qualification](QUALIFICATION.md) | Evidence already collected and live gates that remain external. |
| [Releasing](RELEASING.md) | Self-signed release identity, updater keys, immutable artifacts, qualification, and publication. |

Public releases use one permanent self-signed certificate and are not notarized;
source builds remain ad-hoc signed. Public release integrity additionally
depends on the permanent Tauri updater key and the fail-closed certificate, DR,
and artifact qualification described above.
