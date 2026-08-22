#!/usr/bin/env node

import { readdir, readFile, rename, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const [assetsArgument, tag, repository] = process.argv.slice(2);

if (!assetsArgument || !tag || !repository) {
  console.error(
    "Usage: normalize-release-metadata.mjs <assets-directory> <vVERSION> <owner/repository>",
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
const entries = await readdir(assetsDirectory, { withFileTypes: true });
const files = entries
  .filter((entry) => entry.isFile())
  .map((entry) => entry.name);
const signatureFiles = files.filter((name) => name.endsWith(".app.tar.gz.sig"));

if (signatureFiles.length !== 2) {
  throw new Error(
    `Expected exactly two macOS updater signatures; found ${signatureFiles.length}`,
  );
}

const signatureToArchive = new Map();
for (const signatureName of signatureFiles) {
  const archiveName = signatureName.slice(0, -".sig".length);
  if (archiveName !== basename(archiveName) || !files.includes(archiveName)) {
    throw new Error(`${signatureName} has no matching update archive`);
  }
  const signature = (
    await readFile(join(assetsDirectory, signatureName), "utf8")
  ).trim();
  if (!signature || signatureToArchive.has(signature)) {
    throw new Error("Updater signatures must be nonempty and architecture-specific");
  }
  signatureToArchive.set(signature, archiveName);
}

const metadataPath = join(assetsDirectory, "latest.json");
const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
const expectedVersion = tag.slice(1);

if (metadata.version !== expectedVersion) {
  throw new Error(
    `latest.json has version ${String(metadata.version)}; expected ${expectedVersion}`,
  );
}

const platforms = {};
for (const platform of ["darwin-aarch64", "darwin-x86_64"]) {
  const existing = metadata.platforms?.[platform];
  const signature = existing?.signature?.trim();
  const archiveName = signatureToArchive.get(signature);
  if (!archiveName) {
    throw new Error(`${platform} does not match a detached updater signature`);
  }

  const expectedArchitecture =
    platform === "darwin-aarch64" ? /_aarch64\.app\.tar\.gz$/ : /_x64\.app\.tar\.gz$/;
  if (!expectedArchitecture.test(archiveName)) {
    throw new Error(`${platform} references the wrong architecture archive`);
  }

  platforms[platform] = {
    signature,
    url: `https://github.com/${repository}/releases/download/${tag}/${encodeURIComponent(archiveName)}`,
  };
}

const normalized = {
  version: metadata.version,
  notes: typeof metadata.notes === "string" ? metadata.notes : "",
  pub_date: metadata.pub_date,
  platforms,
};
const temporaryPath = `${metadataPath}.tmp`;
await writeFile(temporaryPath, `${JSON.stringify(normalized, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o644,
});
await rename(temporaryPath, metadataPath);

console.log("Normalized latest.json to immutable exact-tag asset URLs");
