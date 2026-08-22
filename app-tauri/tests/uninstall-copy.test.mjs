import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const uiSource = readFileSync(new URL("../src/main.js", import.meta.url), "utf8");
const englishReadme = readFileSync(
  new URL("../../README.md", import.meta.url),
  "utf8",
);
const russianReadme = readFileSync(
  new URL("../../README.ru.md", import.meta.url),
  "utf8",
);
const rustSource = readFileSync(
  new URL("../src-tauri/src/lib.rs", import.meta.url),
  "utf8",
);
const normalizedEnglishReadme = englishReadme.replace(/\s+/g, " ");
const normalizedRussianReadme = russianReadme.replace(/\s+/g, " ");

const uninstallBodies = [...uiSource.matchAll(/uninstallBody:\s*\n\s*"([^"]+)"/g)].map(
  ([, body]) => body,
);

const legacyLabels = [
  "OsaGuard administrator password",
  "OsaGuard protected product state",
];

test("RU and EN uninstall confirmations disclose legacy Keychain leftovers", () => {
  assert.equal(uninstallBodies.length, 2);
  const [english, russian] = uninstallBodies;

  assert.match(english, /only the current v2 Keychain records/);
  assert.match(english, /previews before 0\.1\.3 are intentionally left untouched/);
  assert.match(english, /Optional cleanup: in Keychain Access/);

  assert.match(russian, /только текущие v2-объекты Связки ключей/);
  assert.match(russian, /preview-версиями до 0\.1\.3, намеренно останутся нетронутыми/);
  assert.match(russian, /в приложении «Связка ключей»/);

  for (const label of legacyLabels) {
    assert.match(english, new RegExp(label));
    assert.match(russian, new RegExp(label));
  }
});

test("both READMEs describe the exact optional pre-0.1.3 cleanup", () => {
  assert.match(normalizedEnglishReadme, /only the current v2 Keychain records/);
  assert.match(
    normalizedEnglishReadme,
    /intentionally does not read or delete unversioned records/,
  );
  assert.match(normalizedEnglishReadme, /preview builds before 0\.1\.3/);

  assert.match(normalizedRussianReadme, /только текущие v2-объекты Связки ключей/);
  assert.match(
    normalizedRussianReadme,
    /намеренно не читает и не удаляет неверсионированные объекты/,
  );
  assert.match(normalizedRussianReadme, /preview-версиями до 0\.1\.3/);

  for (const label of legacyLabels) {
    assert.match(normalizedEnglishReadme, new RegExp(label));
    assert.match(normalizedRussianReadme, new RegExp(label));
  }
});

test("uninstall restores the installed identity before v2 Keychain deletion", () => {
  const start = rustSource.indexOf("async fn uninstall_app");
  const end = rustSource.indexOf("fn maybe_notify_update_available", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const uninstall = rustSource.slice(start, end);

  const moveNeedle = "move_installed_app_to_trash(&trash_plan)?";
  const firstMove = uninstall.indexOf(moveNeedle);
  const restore = uninstall.indexOf("restore_app_from_trash(", firstMove);
  const restoredVerify = uninstall.indexOf(
    "verify_bundle(Path::new(INSTALLED_APP))?;",
    restore,
  );
  const protectedDelete = uninstall.indexOf("delete_protected_state()?;");
  const passwordDelete = uninstall.indexOf("password_delete_all()?;");
  const irreversibleBoundary = uninstall.indexOf("password_deleted = true;");
  const finalMove = uninstall.indexOf(moveNeedle, firstMove + moveNeedle.length);

  for (const position of [
    firstMove,
    restore,
    restoredVerify,
    protectedDelete,
    passwordDelete,
    irreversibleBoundary,
    finalMove,
  ]) {
    assert.notEqual(position, -1);
  }
  assert.ok(firstMove < restore);
  assert.ok(restore < restoredVerify);
  assert.ok(restoredVerify < protectedDelete);
  assert.ok(protectedDelete < passwordDelete);
  assert.ok(passwordDelete < irreversibleBoundary);
  assert.ok(irreversibleBoundary < finalMove);
  assert.equal(uninstall.indexOf(moveNeedle, finalMove + moveNeedle.length), -1);
  assert.match(uninstall, /if !password_deleted \{/);
});
