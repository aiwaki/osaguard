import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const normalizeScript = join(
  scriptsDirectory,
  "normalize-release-metadata.mjs",
);
const generateMetadataScript = join(
  scriptsDirectory,
  "generate-release-metadata.mjs",
);
const validateScript = join(scriptsDirectory, "validate-release-assets.mjs");
const verifySignatureScript = join(
  scriptsDirectory,
  "verify-updater-signature.mjs",
);
const tag = "v0.1.1";
const repository = "aiwaki/osaguard";

async function makeFixture() {
  const directory = await mkdtemp(join(tmpdir(), "osaguard-release-test-"));
  const armArchive = "OsaGuard_0.1.1_aarch64.app.tar.gz";
  const intelArchive = "OsaGuard_0.1.1_x64.app.tar.gz";
  const armSignature = "arm-signature";
  const intelSignature = "intel-signature";

  await Promise.all([
    writeFile(join(directory, armArchive), "arm-archive"),
    writeFile(join(directory, `${armArchive}.sig`), `${armSignature}\n`),
    writeFile(join(directory, intelArchive), "intel-archive"),
    writeFile(join(directory, `${intelArchive}.sig`), `${intelSignature}\n`),
    writeFile(join(directory, "OsaGuard_0.1.1_aarch64.dmg"), "arm-dmg"),
    writeFile(join(directory, "OsaGuard_0.1.1_x64.dmg"), "intel-dmg"),
  ]);

  return { directory, armSignature, intelSignature };
}

function run(script, directory) {
  return spawnSync(process.execPath, [script, directory, tag, repository], {
    encoding: "utf8",
  });
}

function makeUpdaterSignature(data, filename) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const rawPublicKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const keyId = Buffer.from("0102030405060708", "hex");
  const publicKeyBox = Buffer.concat([
    Buffer.from("Ed", "ascii"),
    keyId,
    rawPublicKey,
  ]);
  const publicKeyText = `untrusted comment: minisign public key\n${publicKeyBox.toString("base64")}\n`;

  const digest = createHash("blake2b512").update(data).digest();
  const archiveSignature = sign(null, digest, privateKey);
  const trustedComment = `timestamp:1786622400\tfile:${filename}`;
  const globalSignature = sign(
    null,
    Buffer.concat([archiveSignature, Buffer.from(trustedComment)]),
    privateKey,
  );
  const signatureBox = Buffer.concat([
    Buffer.from("ED", "ascii"),
    keyId,
    archiveSignature,
  ]);
  const signatureText = [
    "untrusted comment: signature from tauri secret key",
    signatureBox.toString("base64"),
    `trusted comment: ${trustedComment}`,
    globalSignature.toString("base64"),
    "",
  ].join("\n");

  return {
    publicKey: Buffer.from(publicKeyText).toString("base64"),
    signature: Buffer.from(signatureText).toString("base64"),
  };
}

test("generates immutable updater metadata and validates both architectures", async () => {
  const fixture = await makeFixture();
  try {
    const generated = run(generateMetadataScript, fixture.directory);
    assert.equal(generated.status, 0, generated.stderr);
    const normalized = run(normalizeScript, fixture.directory);
    assert.equal(normalized.status, 0, normalized.stderr);

    const metadata = JSON.parse(
      await readFile(join(fixture.directory, "latest.json"), "utf8"),
    );
    assert.deepEqual(Object.keys(metadata.platforms).sort(), [
      "darwin-aarch64",
      "darwin-x86_64",
    ]);
    assert.equal(
      metadata.platforms["darwin-aarch64"].url,
      "https://github.com/aiwaki/osaguard/releases/download/v0.1.1/OsaGuard_0.1.1_aarch64.app.tar.gz",
    );
    assert.equal(
      metadata.platforms["darwin-x86_64"].url,
      "https://github.com/aiwaki/osaguard/releases/download/v0.1.1/OsaGuard_0.1.1_x64.app.tar.gz",
    );

    const validated = run(validateScript, fixture.directory);
    assert.equal(validated.status, 0, validated.stderr);
    assert.match(validated.stdout, /^darwin-aarch64\tarm64\t/m);
    assert.match(validated.stdout, /^darwin-x86_64\tx86_64\t/m);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("rejects a platform mapped to the other architecture signature", async () => {
  const fixture = await makeFixture();
  try {
    assert.equal(run(generateMetadataScript, fixture.directory).status, 0);
    const metadataPath = join(fixture.directory, "latest.json");
    const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
    metadata.platforms["darwin-aarch64"].signature = fixture.intelSignature;
    await writeFile(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`);

    const result = run(normalizeScript, fixture.directory);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /wrong architecture archive/);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("rejects canonical metadata with a mutable latest URL", async () => {
  const fixture = await makeFixture();
  try {
    assert.equal(run(generateMetadataScript, fixture.directory).status, 0);
    assert.equal(run(normalizeScript, fixture.directory).status, 0);
    const metadataPath = join(fixture.directory, "latest.json");
    const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
    metadata.platforms["darwin-aarch64"].url =
      "https://github.com/aiwaki/osaguard/releases/latest/download/OsaGuard_0.1.1_aarch64.app.tar.gz";
    await writeFile(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`);

    const result = run(validateScript, fixture.directory);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unexpected release URL/);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("rejects a stale artifact mixed into the draft", async () => {
  const fixture = await makeFixture();
  try {
    assert.equal(run(generateMetadataScript, fixture.directory).status, 0);
    assert.equal(run(normalizeScript, fixture.directory).status, 0);
    await writeFile(join(fixture.directory, "OsaGuard_0.1.0_aarch64.dmg"), "stale");

    const result = run(validateScript, fixture.directory);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /DMGs are|Release asset set mismatch/);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("refuses to overwrite or derive metadata from a mixed release asset set", async () => {
  const fixture = await makeFixture();
  try {
    await writeFile(join(fixture.directory, "unexpected.zip"), "unexpected");
    const mixed = run(generateMetadataScript, fixture.directory);
    assert.notEqual(mixed.status, 0);
    assert.match(mixed.stderr, /exact two-architecture set/);

    await rm(join(fixture.directory, "unexpected.zip"));
    assert.equal(run(generateMetadataScript, fixture.directory).status, 0);
    const overwrite = run(generateMetadataScript, fixture.directory);
    assert.notEqual(overwrite.status, 0);
    assert.match(overwrite.stderr, /overwrite an existing latest.json/);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("cryptographically verifies a Tauri updater signature", async () => {
  const directory = await mkdtemp(join(tmpdir(), "osaguard-signature-test-"));
  try {
    const archiveName = "OsaGuard_0.1.1_aarch64.app.tar.gz";
    const archivePath = join(directory, archiveName);
    const signaturePath = `${archivePath}.sig`;
    const data = Buffer.from("signed updater archive");
    const updaterSignature = makeUpdaterSignature(data, archiveName);
    await writeFile(archivePath, data);
    await writeFile(signaturePath, updaterSignature.signature);
    const publicKeyPath = join(directory, "updater.pub");
    await writeFile(publicKeyPath, `${updaterSignature.publicKey}\n`);

    const verified = spawnSync(
      process.execPath,
      [verifySignatureScript, archivePath, signaturePath, publicKeyPath],
      { encoding: "utf8" },
    );
    assert.equal(verified.status, 0, verified.stderr);

    await writeFile(archivePath, "tampered updater archive");
    const rejected = spawnSync(
      process.execPath,
      [verifySignatureScript, archivePath, signaturePath, publicKeyPath],
      { encoding: "utf8" },
    );
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /signature verification failed/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
