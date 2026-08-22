# Third-party notices

OsaGuard is licensed under the MIT License. It also uses third-party software
that remains subject to its own license terms.

Notable direct and platform dependencies include:

| Component | Use | License |
| --- | --- | --- |
| [makc](https://github.com/aiwaki/makc) | macOS keyboard-state integration | MIT |
| [Tauri](https://github.com/tauri-apps/tauri) | desktop application framework | MIT or Apache-2.0 |
| [Tauri plugins](https://github.com/tauri-apps/plugins-workspace) | single-instance, launch-at-login, notifications, process control, and updater features | MIT or Apache-2.0 |
| [Rust `trash`](https://github.com/Byron/trash-rs) | moving the installed app to the macOS Trash during uninstall | MIT |
| [Rust `libc`](https://github.com/rust-lang/libc) | platform bindings | MIT or Apache-2.0 |
| [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) | operating-system interfaces | BSD-3-Clause |
| [`golang.org/x/term`](https://pkg.go.dev/golang.org/x/term) | secure terminal input for developer tooling | BSD-3-Clause |
| [purego](https://github.com/ebitengine/purego) | Go platform interop used by makc | Apache-2.0 |
| [godbus/dbus](https://github.com/godbus/dbus) | transitive platform support used by makc | BSD-2-Clause |

The exact dependency versions for a source checkout are recorded in `go.mod`,
`go.sum`, `app-tauri/package-lock.json`, and `app-tauri/src-tauri/Cargo.lock`.
Those files include additional transitive dependencies not individually listed
above. Redistributors are responsible for preserving all notices and license
texts required by the versions they ship.

OsaGuard links to Apple system frameworks available as part of macOS; those
frameworks are not distributed by this repository and remain subject to Apple's
terms.

This notice is informational. If it conflicts with an upstream license file,
the upstream license terms control.
