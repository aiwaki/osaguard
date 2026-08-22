#!/usr/bin/env node

import { readdir, readFile, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const [assetsArgument, tag, repository] = process.argv.slice(2);

if (!assetsArgument || !tag || !repository) {
  console.error(
    "Usage: validate-release-assets.mjs <assets-directory> <vVERSION> <owner/repository>",
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
const files = new Set(
  entries.filter((entry) => entry.isFile()).map((entry) => entry.name),
);

if (!files.has("latest.json")) {
  throw new Error("The draft release does not contain latest.json");
}

const metadata = JSON.parse(
  await readFile(join(assetsDirectory, "latest.json"), "utf8"),
);
const expectedVersion = tag.slice(1);

if (metadata.version !== expectedVersion) {
  throw new Error(
    `latest.json has version ${String(metadata.version)}; expected ${expectedVersion}`,
  );
}

if (typeof metadata.pub_date !== "string" || Number.isNaN(Date.parse(metadata.pub_date))) {
  throw new Error("latest.json must contain a valid pub_date");
}

const expectedPlatforms = new Map([
  ["darwin-aarch64", "arm64"],
  ["darwin-x86_64", "x86_64"],
]);
const expectedUpdaterArchives = new Map([
  ["darwin-aarch64", `OsaGuard_${expectedVersion}_aarch64.app.tar.gz`],
  ["darwin-x86_64", `OsaGuard_${expectedVersion}_x64.app.tar.gz`],
]);
const actualPlatforms = Object.keys(metadata.platforms ?? {}).sort();
const expectedPlatformNames = [...expectedPlatforms.keys()].sort();

if (JSON.stringify(actualPlatforms) !== JSON.stringify(expectedPlatformNames)) {
  throw new Error(
    `latest.json platforms are ${actualPlatforms.join(", ") || "empty"}; expected ${expectedPlatformNames.join(", ")}`,
  );
}

const artifactNames = new Set();
const rows = [];

for (const [platform, architecture] of expectedPlatforms) {
  const release = metadata.platforms[platform];
  if (!release || typeof release.url !== "string") {
    throw new Error(`${platform} is missing an update URL`);
  }
  if (typeof release.signature !== "string" || release.signature.trim() === "") {
    throw new Error(`${platform} is missing an updater signature`);
  }

  const url = new URL(release.url);
  const expectedPrefix = `/${repository}/releases/download/${tag}/`;
  if (
    url.protocol !== "https:" ||
    url.hostname !== "github.com" ||
    !url.pathname.startsWith(expectedPrefix) ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error(`${platform} has an unexpected release URL: ${release.url}`);
  }

  const artifactName = decodeURIComponent(url.pathname.slice(expectedPrefix.length));
  if (
    artifactName !== basename(artifactName) ||
    !artifactName.endsWith(".app.tar.gz") ||
    artifactName.includes("\0")
  ) {
    throw new Error(`${platform} has an unsafe or unsupported artifact name`);
  }
  if (artifactName !== expectedUpdaterArchives.get(platform)) {
    throw new Error(
      `${platform} references ${artifactName}; expected ${expectedUpdaterArchives.get(platform)}`,
    );
  }
  if (artifactNames.has(artifactName)) {
    throw new Error("The two macOS platforms must use different update archives");
  }
  artifactNames.add(artifactName);

  const signatureName = `${artifactName}.sig`;
  for (const name of [artifactName, signatureName]) {
    if (!files.has(name)) {
      throw new Error(`${platform} references missing release asset ${name}`);
    }
    const details = await stat(join(assetsDirectory, name));
    if (!details.isFile() || details.size === 0) {
      throw new Error(`${name} is empty or is not a regular file`);
    }
  }

  const detachedSignature = (
    await readFile(join(assetsDirectory, signatureName), "utf8")
  ).trim();
  if (release.signature.trim() !== detachedSignature) {
    throw new Error(
      `${platform} signature does not match ${signatureName}`,
    );
  }

  rows.push([platform, architecture, join(assetsDirectory, artifactName)]);
}

const actualUpdaterArchives = [...files]
  .filter((name) => name.endsWith(".app.tar.gz"))
  .sort();
const expectedUpdaterArchiveNames = [...expectedUpdaterArchives.values()].sort();
if (
  JSON.stringify(actualUpdaterArchives) !==
  JSON.stringify(expectedUpdaterArchiveNames)
) {
  throw new Error(
    `Updater archives are ${actualUpdaterArchives.join(", ") || "empty"}; expected ${expectedUpdaterArchiveNames.join(", ")}`,
  );
}

const diskImages = [...files].filter((name) => name.endsWith(".dmg")).sort();
const expectedDiskImages = [
  `OsaGuard_${expectedVersion}_aarch64.dmg`,
  `OsaGuard_${expectedVersion}_x64.dmg`,
].sort();
if (JSON.stringify(diskImages) !== JSON.stringify(expectedDiskImages)) {
  throw new Error(
    `DMGs are ${diskImages.join(", ") || "empty"}; expected ${expectedDiskImages.join(", ")}`,
  );
}

const expectedAssets = new Set([
  "latest.json",
  ...expectedUpdaterArchiveNames,
  ...expectedUpdaterArchiveNames.map((name) => `${name}.sig`),
  ...expectedDiskImages,
]);
const unexpectedAssets = [...files]
  .filter((name) => !expectedAssets.has(name))
  .sort();
const missingAssets = [...expectedAssets]
  .filter((name) => !files.has(name))
  .sort();
if (unexpectedAssets.length > 0 || missingAssets.length > 0) {
  throw new Error(
    `Release asset set mismatch; unexpected: ${unexpectedAssets.join(", ") || "none"}; missing: ${missingAssets.join(", ") || "none"}`,
  );
}

for (const row of rows) {
  process.stdout.write(`${row.join("\t")}\n`);
}
