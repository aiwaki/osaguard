import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const bootstrap = await readFile(join(scriptDirectory, "bootstrap-release-credentials.sh"), "utf8");

test("release credential bootstrap stays outside Keychain services", () => {
  assert.match(bootstrap, /identity_name='OsaGuard Release Code Signing'/);
  assert.match(bootstrap, /openssl req -x509/);
  assert.match(bootstrap, /extendedKeyUsage = critical,codeSigning/);
  assert.match(bootstrap, /openssl pkcs12 -export -legacy/);
  assert.match(bootstrap, /signer generate --ci/);
  assert.match(bootstrap, /chmod 700/);
  assert.match(bootstrap, /chmod 600/);
  assert.doesNotMatch(bootstrap, /\bsecurity\b/);
  assert.doesNotMatch(bootstrap, /list-keychains/);
});
