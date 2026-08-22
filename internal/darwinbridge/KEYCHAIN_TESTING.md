# Keychain test safety

`go test ./...` must never create, modify, or delete an item in a developer's
login Keychain. The bridge's production Keychain calls intentionally omit a
test-only `kSecUseKeychain` selector, so an in-process test would otherwise use
the active user's default Keychain.

The former `OSAGUARD_KEYCHAIN_INTEGRATION=1` tests were removed. In particular,
the ACL-poisoning test created the real `dev.aiwaki.osaguard.integrity-state`
item and then attempted to replace its access owner. macOS correctly displayed
a SecurityAgent request for the login Keychain password. Do not set that
environment variable: the remaining guard test fails before any Keychain API is
called.

Starting with the persistent-signing preview, production uses the versioned
`admin-password.v2` and `integrity-state.v2` services. The app must never query,
read, change, or delete the unversioned items created by earlier ad-hoc builds:
touching their old ACL is what causes the repeated SecurityAgent ownership
prompts. Consequently, uninstall removes only items owned in the active v2
namespace. A legacy item can be removed separately with the older trusted build
or Keychain Access; automated qualification must leave it untouched.

Do live Keychain qualification manually only in a disposable macOS account or
VM that contains no real user secrets. Do not switch the default Keychain or
search list from an automated test: those preferences are user-wide and can
break concurrently running applications or remain changed after a crash.

Manual qualification in that disposable environment should cover:

1. Save an administrator password, then change it; confirm the new value works.
2. Cancel a change; confirm no error is shown and the old value is retained.
3. With one standalone CLI binary, save through more than one supported
   account-label path, then run that same binary's `forget-password` action;
   confirm every caller-only record it owns is gone. The public app must never
   delete a record whose ACL identifies a different executable.
4. In that disposable account only, add a same-service generic-password item
   with an ACL that does not trust OsaGuard. Removal and uninstall must fail
   before deleting any caller-only OsaGuard record; they must never delete the
   unrecognized item or claim success.
5. Restart the app; confirm its protected enabled/paused state is retained.

No development, CI, or release workflow may opt into a live Keychain test on a
normal user profile.
