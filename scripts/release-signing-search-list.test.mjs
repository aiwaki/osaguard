import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = dirname(scriptsDirectory);

test("release signing snapshots and restores the exact user Keychain search list", async () => {
  const [importScript, restoreScript, workflow] = await Promise.all([
    readFile(join(scriptsDirectory, "import-release-signing-identity.sh"), "utf8"),
    readFile(
      join(scriptsDirectory, "restore-release-signing-keychain-search-list.sh"),
      "utf8",
    ),
    readFile(join(repositoryDirectory, ".github", "workflows", "release.yml"), "utf8"),
  ]);

  assert.match(importScript, /security list-keychains -d user > "\$search_list_snapshot"/);
  assert.match(importScript, /OSAGUARD_CODE_SIGNING_SEARCH_LIST_SNAPSHOT=/);
  assert.match(importScript, /restore-release-signing-keychain-search-list\.sh/);
  assert.match(
    importScript,
    /\[\[ "\$complete" != true && "\$search_list_changed" == true \]\]/,
  );
  assert.match(importScript, /if \[\[ "\$complete" != true && "\$recovery_required" != true \]\]/);
  assert.match(importScript, /Preserved temporary signing Keychain and search-list snapshot/);
  assert.match(restoreScript, /security list-keychains -d user -s "\$\{keychains\[@\]\}"/);
  assert.match(restoreScript, /did not restore exactly/);

  const cleanupStart = workflow.indexOf("- name: Remove temporary release signing keychain");
  const cleanup = workflow.slice(cleanupStart);
  const restoreCall = workflow.indexOf(
    "scripts/restore-release-signing-keychain-search-list.sh",
    cleanupStart,
  );
  const deleteCall = workflow.indexOf("security delete-keychain", cleanupStart);
  assert.ok(cleanupStart >= 0);
  assert.ok(restoreCall > cleanupStart);
  assert.ok(deleteCall > restoreCall);
  const restoreFailure = cleanup.indexOf('if [[ "$search_list_restored" != true ]]; then');
  const verifiedRestore = cleanup.indexOf(
    'elif [[ "$keychain_valid" == true && "$snapshot_valid" == true ]]; then',
  );
  assert.ok(restoreFailure >= 0);
  assert.ok(verifiedRestore > restoreFailure);
  assert.match(cleanup, /preserving temporary signing material/);
  assert.doesNotMatch(
    cleanup.slice(restoreFailure, verifiedRestore),
    /security delete-keychain|\/bin\/rm -f/,
  );
  assert.match(cleanup.slice(verifiedRestore), /security delete-keychain/);
});
