#!/usr/bin/env node

import { readdir, readFile, rename, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const [assetsArgument, tag, repository] = process.argv.slice(2);

if (!assetsArgument || !tag || !repository) {
  console.error(
    "Usage: generate-release-metadata.mjs <assets-directory> <vVERSION> <owner/repository>",
  );
  process.exit(1);
}

if (!/^v\d+\.\d+\.\d+(?:[.-][0-9A-Za-z.-]+)?$/.test(tag)) {
  throw new Error(`Invalid release tag: ${tag}`);
}

if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
  throw new Error(`Invalid repository: ${repository}`);
}

const assetsDirectory = resolve(assetsArgument);
const version = tag.slice(1);
const expectedArchives = new Map([
  ["darwin-aarch64", `OsaGuard_${version}_aarch64.app.tar.gz`],
  ["darwin-x86_64", `OsaGuard_${version}_x64.app.tar.gz`],
]);
const expectedDiskImages = new Set([
  `OsaGuard_${version}_aarch64.dmg`,
  `OsaGuard_${version}_x64.dmg`,
]);
const expectedAssets = new Set([
  ...expectedArchives.values(),
  ...[...expectedArchives.values()].map((archive) => `${archive}.sig`),
  ...expectedDiskImages,
]);

const entries = await readdir(assetsDirectory, { withFileTypes: true });
const files = new Set(
  entries.filter((entry) => entry.isFile()).map((entry) => entry.name),
);

if (files.has("latest.json")) {
  throw new Error("Refusing to overwrite an existing latest.json");
}

const unexpected = [...files].filter((name) => !expectedAssets.has(name)).sort();
const missing = [...expectedAssets].filter((name) => !files.has(name)).sort();
if (unexpected.length > 0 || missing.length > 0) {
  throw new Error(
    `Release assets do not form one exact two-architecture set; unexpected: ${unexpected.join(", ") || "none"}; missing: ${missing.join(", ") || "none"}`,
  );
}

const platforms = {};
for (const [platform, archive] of expectedArchives) {
  if (archive !== basename(archive)) {
    throw new Error(`Unsafe archive name: ${archive}`);
  }
  const signature = (await readFile(join(assetsDirectory, `${archive}.sig`), "utf8")).trim();
  if (signature.length === 0) {
    throw new Error(`${archive}.sig is empty`);
  }
  platforms[platform] = {
    signature,
    url: `https://github.com/${repository}/releases/download/${tag}/${encodeURIComponent(archive)}`,
  };
}

const metadataPath = join(assetsDirectory, "latest.json");
const temporaryPath = `${metadataPath}.tmp`;
const metadata = {
  version,
  notes: "",
  pub_date: new Date().toISOString(),
  platforms,
};
await writeFile(temporaryPath, `${JSON.stringify(metadata, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o644,
});
await rename(temporaryPath, metadataPath);

console.log("Generated immutable Tauri updater metadata from the qualified draft assets");
