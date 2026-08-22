# Security Policy

OsaGuard stores and automatically uses an administrator password, so security
reports are especially important. Please do not publish vulnerability details
before a fix or mitigation is available.

## Supported versions

Only the newest stable version published on the
[Releases page](https://github.com/aiwaki/osaguard/releases/latest) is
supported. Older versions may be asked to update before a report is
investigated further. Unreleased changes on `main` receive fixes on a
best-effort basis.

## Report a vulnerability privately

Preferred: submit a
[private GitHub vulnerability report](https://github.com/aiwaki/osaguard/security/advisories/new).

Include only what is needed to reproduce and assess the problem:

- affected version, commit, and macOS version;
- whether the build came from Releases or was built locally;
- a concise description of the impact and required attacker access;
- minimal reproduction steps or a small proof of concept;
- relevant logs with passwords, usernames, paths, tokens, and personal data
  removed;
- any suggested mitigation, if known.

If private vulnerability reporting is unavailable, open a public issue titled
`Security contact requested` with no vulnerability details. A maintainer can
then arrange a private channel. Never put a password, Keychain export, live
credential, or unredacted authentication screenshot in any report.

The maintainers aim to acknowledge a complete report within seven days, provide
an initial assessment within fourteen days, and coordinate disclosure after a
fix. These are targets, not guaranteed response times.

## High-value report areas

Examples include:

- exposure of the password through logs, files, argv, environment variables,
  clipboard data, JavaScript, IPC, crash output, or network traffic;
- unauthorized retrieval or replacement of the OsaGuard Keychain item;
- input sent to an unverified, non-Apple, or wrong authorization process;
- bypass of process, code-signing, secure-field, session, or prompt-stability
  checks;
- unsafe installation, update-signature bypass, or privilege escalation beyond
  the documented behavior;
- a way for remote or another-user code to activate automatic approval without
  first gaining access to the configured macOS account;
- secret remnants that remain accessible after **Remove stored password** or a
  complete uninstall.

## Documented risk is not by itself a vulnerability

Automatic confirmation intentionally has a severe limitation: code already
running as the configured macOS user may start a supported AppleScript
administrator request, which OsaGuard may approve without another human action.
OsaGuard can therefore act as a passwordless-root oracle for same-user code.

There is also an unavoidable causal ambiguity in the supported flow. Public
macOS Accessibility and CGWindow APIs identify SecurityAgent as the owner of an
administrator dialog, but do not reveal or bind that dialog to the client that
requested authorization. OsaGuard uses short, best-effort temporal correlation,
not cryptographic or OS-enforced requester-to-dialog attribution. A different
genuine SecurityAgent administrator dialog appearing in the same short matching
window may therefore receive the saved password.

A report should show an impact beyond that clearly acknowledged boundary, such
as activation without explicit setup and risk acknowledgement, secret
extraction, handling of a non-Apple authorization process, widening the bounded
correlation window, or bypass of a documented guard. The known limitations do
not make related implementation defects out of scope.

## Coordinated disclosure and safe harbor

Please act in good faith, test only systems and accounts you own or are
authorized to test, avoid privacy violations and persistence, and stop once you
have enough evidence. Do not use a discovered issue to access other people's
data or publish working exploit details before coordination.

The project will not pursue legal action against good-faith research that
follows this policy. This statement does not authorize actions prohibited by
third parties or applicable law.
