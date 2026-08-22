import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const generator = join(scriptsDirectory, "generate-preview-release-metadata.mjs");

test("generates an immutable exact-tag Apple Silicon preview appcast", async () => {
  const directory = await mkdtemp(join(tmpdir(), "osaguard-preview-appcast-"));
  try {
    await writeFile(join(directory, "OsaGuard.app.tar.gz"), "archive");
    await writeFile(join(directory, "OsaGuard.app.tar.gz.sig"), "signature\n");
    const result = spawnSync(
      process.execPath,
      [generator, directory, "v0.1.3-preview.2", "aiwaki/osaguard"],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    const metadata = JSON.parse(
      await readFile(join(directory, "latest.json"), "utf8"),
    );
    assert.equal(metadata.version, "0.1.3-preview.2");
    assert.deepEqual(Object.keys(metadata.platforms), ["darwin-aarch64"]);
    assert.equal(
      metadata.platforms["darwin-aarch64"].url,
      "https://github.com/aiwaki/osaguard/releases/download/v0.1.3-preview.2/OsaGuard.app.tar.gz",
    );
    assert.equal(metadata.platforms["darwin-aarch64"].signature, "signature");

    const overwrite = spawnSync(
      process.execPath,
      [generator, directory, "v0.1.3-preview.2", "aiwaki/osaguard"],
      { encoding: "utf8" },
    );
    assert.notEqual(overwrite.status, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects a stable-looking tag for the preview appcast", async () => {
  const directory = await mkdtemp(join(tmpdir(), "osaguard-preview-appcast-"));
  try {
    await writeFile(join(directory, "OsaGuard.app.tar.gz"), "archive");
    await writeFile(join(directory, "OsaGuard.app.tar.gz.sig"), "signature\n");
    const result = spawnSync(
      process.execPath,
      [generator, directory, "v0.1.3", "aiwaki/osaguard"],
      { encoding: "utf8" },
    );
    assert.notEqual(result.status, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
