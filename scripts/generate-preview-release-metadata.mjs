#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const [assetsArgument, tag, repository] = process.argv.slice(2);
if (!assetsArgument || !tag || !repository) {
  console.error(
    "Usage: generate-preview-release-metadata.mjs <assets-directory> <vVERSION-preview.N> <owner/repository>",
  );
  process.exit(1);
}
if (!/^v\d+\.\d+\.\d+-preview\.[1-9][0-9]*$/.test(tag)) {
  throw new Error(`Invalid preview tag: ${tag}`);
}
if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
  throw new Error(`Invalid repository: ${repository}`);
}

const assetsDirectory = resolve(assetsArgument);
const archiveName = "OsaGuard.app.tar.gz";
const signatureName = `${archiveName}.sig`;
if (archiveName !== basename(archiveName)) {
  throw new Error("Unsafe updater archive name");
}
const signature = (
  await readFile(join(assetsDirectory, signatureName), "utf8")
).trim();
if (!signature) {
  throw new Error("Updater signature is empty");
}

const metadata = {
  version: tag.slice(1),
  notes: "See the release notes.",
  pub_date: new Date().toISOString(),
  platforms: {
    "darwin-aarch64": {
      signature,
      url: `https://github.com/${repository}/releases/download/${tag}/${archiveName}`,
    },
  },
};
await writeFile(
  join(assetsDirectory, "latest.json"),
  `${JSON.stringify(metadata, null, 2)}\n`,
  { encoding: "utf8", mode: 0o644, flag: "wx" },
);
console.log("Generated immutable Apple Silicon preview updater metadata");
