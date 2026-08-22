# OsaGuard Tauri application

This directory contains the Tauri v2 menu-bar application and its small
HTML/CSS/JavaScript dashboard. OsaGuard uses accessory activation on macOS, so it
normally appears in the menu bar without a Dock icon. The dashboard window is
created hidden and opens for setup, status, the security warning, and update
confirmation.

The Tauri main process owns the macOS Accessibility request and starts the
bundled Go watcher as a direct child. The application itself, not a separate
watcher LaunchAgent, is registered to start at login. Pausing, quitting,
updating, uninstalling, or shutting down the app stops and reaps the child.

The WebView never receives the administrator password. A direct password action
from the menu or dashboard starts the bundled helper, which displays a native
AppKit secure-text window and writes to the user's login Keychain. Cancel is a
normal no-op. Release users do not need Terminal after installation.

Official builds embed the stable GitHub endpoint and permanent Tauri updater
public key. Update metadata and packages are signed, installation requires user
confirmation, and native notifications have a tray-menu fallback. Local builds
leave the updater unconfigured. **Uninstall OsaGuard…** confirms the action,
stops the watcher and login startup, removes the Keychain secret and settings,
resets Accessibility, and moves the app to the Trash.

Developer checks and a local ad-hoc build:

```sh
make check
make tray-build
```

The local app is written under
`src-tauri/target/release/bundle/macos/OsaGuard.app`. Release configuration is
generated only in CI; see [the release procedure](../docs/RELEASING.md).
