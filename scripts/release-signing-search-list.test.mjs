import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = dirname(scriptsDirectory);
const importerPath = join(scriptsDirectory, "import-release-signing-identity.sh");
const signingIdentity = "OsaGuard Release Code Signing";

function matchingIdentityCount(listing) {
  const result = spawnSync(
    "/bin/bash",
    [
      "-c",
      'source "$1"; count_matching_code_signing_identities "$2"',
      "bash",
      importerPath,
      signingIdentity,
    ],
    { encoding: "utf8", input: listing },
  );
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

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
  assert.match(importScript, /\[\[ -f "\$search_list_snapshot" && ! -L "\$search_list_snapshot" \]\]/);
  assert.match(importScript, /OSAGUARD_CODE_SIGNING_SEARCH_LIST_SNAPSHOT=/);
  assert.match(importScript, /restore-release-signing-keychain-search-list\.sh/);
  assert.match(
    importScript,
    /\[\[ "\$complete" != true && "\$search_list_changed" == true \]\]/,
  );
  assert.match(importScript, /if \[\[ "\$complete" != true && "\$recovery_required" != true \]\]/);
  assert.match(importScript, /Preserved temporary signing Keychain and search-list snapshot/);
  assert.match(restoreScript, /security list-keychains -d user -s "\$\{keychains\[@\]\}"/);
  assert.match(
    importScript,
    /if \[\[ \$\{#existing_keychains\[@\]\} -eq 0 \]\]; then[\s\S]*?security list-keychains -d user -s "\$keychain_path"/,
  );
  assert.match(
    restoreScript,
    /if \[\[ \$\{#keychains\[@\]\} -eq 0 \]\]; then[\s\S]*?security list-keychains -d user -s\n/,
  );
  assert.doesNotMatch(importScript, /search list is empty; refusing/);
  assert.doesNotMatch(restoreScript, /search-list snapshot is empty/);
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

test("release signing authenticates the P12 in its ephemeral keychain before changing the user search list", async () => {
  const importScript = await readFile(
    join(scriptsDirectory, "import-release-signing-identity.sh"),
    "utf8",
  );

  const certificateLookup = importScript.indexOf(
    '/usr/bin/security find-certificate -c "$signing_identity" -p "$keychain_path"',
  );
  const fingerprintCheck = importScript.indexOf(
    'if [[ "$actual_fingerprint" != "$expected_fingerprint" ]]',
  );
  const expiryCheck = importScript.indexOf(
    '/usr/bin/openssl x509 -in "$certificate_path" -noout -checkend 0',
  );
  const identityLookup = importScript.indexOf(
    'identity_listing=$(/usr/bin/security find-identity -p codesigning "$keychain_path")',
  );
  const snapshotSearchList = importScript.indexOf(
    '/usr/bin/security list-keychains -d user > "$search_list_snapshot"',
  );
  const mutateSearchList = importScript.indexOf(
    '/usr/bin/security list-keychains -d user -s "$keychain_path"',
  );

  assert.ok(certificateLookup >= 0);
  assert.ok(fingerprintCheck > certificateLookup);
  assert.ok(expiryCheck > fingerprintCheck);
  assert.ok(identityLookup > expiryCheck);
  assert.ok(snapshotSearchList > identityLookup);
  assert.ok(mutateSearchList > snapshotSearchList);
  assert.match(importScript, /not use `security add-trusted-cert`/);
  assert.doesNotMatch(importScript, /^\s*\/usr\/bin\/security add-trusted-cert/m);
  assert.match(
    importScript,
    /security import "\$p12_path"[\s\S]*?-A[\s\S]*?-t cert[\s\S]*?-f pkcs12/,
  );
  assert.match(importScript, /set-key-partition-list[\s\S]*?apple-tool:,apple:[\s\S]*?-t private/);
  assert.doesNotMatch(importScript, /security import[\s\S]*?\n\s*-T \/usr\/bin\/(?:codesign|security)/);
});

test("release signing counts only matching identities regardless of Trust Settings", () => {
  const untrusted = `
Policy: Code Signing
  Matching identities
  1) 0123456789ABCDEF0123456789ABCDEF01234567 "${signingIdentity}"
     1 identities found

  Valid identities only
     0 valid identities found
`;
  const globallyTrusted = `
Policy: Code Signing
  Matching identities
  1) 0123456789ABCDEF0123456789ABCDEF01234567 "${signingIdentity}"
     1 identities found

  Valid identities only
  1) 0123456789ABCDEF0123456789ABCDEF01234567 "${signingIdentity}"
     1 valid identities found
`;

  assert.equal(matchingIdentityCount(untrusted), "1");
  assert.equal(matchingIdentityCount(globallyTrusted), "1");
});
