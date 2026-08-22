#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const projectDir = dirname(scriptDir);
const packageJson = JSON.parse(
  await readFile(join(projectDir, "app-tauri", "package.json"), "utf8"),
);
const tauriConfig = JSON.parse(
  await readFile(
    join(projectDir, "app-tauri", "src-tauri", "tauri.conf.json"),
    "utf8",
  ),
);
const cargoToml = await readFile(
  join(projectDir, "app-tauri", "src-tauri", "Cargo.toml"),
  "utf8",
);
const goMain = await readFile(
  join(projectDir, "cmd", "osaguard", "main.go"),
  "utf8",
);
const changelog = await readFile(join(projectDir, "CHANGELOG.md"), "utf8");
const cargoPackage = cargoToml.match(
  /^\[package\][\s\S]*?^version\s*=\s*"([^"]+)"/m,
);
const goVersion = goMain.match(/^const version\s*=\s*"([^"]+)"/m);

if (!cargoPackage || !goVersion) {
  console.error("Could not read the Rust or Go package version");
  process.exit(1);
}

const versions = new Map([
  ["app-tauri/package.json", packageJson.version],
  ["app-tauri/src-tauri/tauri.conf.json", tauriConfig.version],
  ["app-tauri/src-tauri/Cargo.toml", cargoPackage[1]],
  ["cmd/osaguard/main.go", goVersion[1]],
]);
const expectedVersion = packageJson.version;
const mismatches = [...versions].filter(([, version]) => version !== expectedVersion);

if (mismatches.length > 0) {
  for (const [file, version] of mismatches) {
    console.error(`${file} has version ${version}; expected ${expectedVersion}`);
  }
  process.exit(1);
}

const escapedVersion = expectedVersion.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
if (!new RegExp(`^## \\[${escapedVersion}\\](?: - \\d{4}-\\d{2}-\\d{2})?$`, "m").test(changelog)) {
  console.error(`CHANGELOG.md has no release section for ${expectedVersion}`);
  process.exit(1);
}

if (process.env.GITHUB_REF_TYPE === "tag") {
  const expectedTag = `v${expectedVersion}`;
  if (process.env.GITHUB_REF_NAME !== expectedTag) {
    console.error(
      `Release tag ${process.env.GITHUB_REF_NAME} does not match ${expectedTag}`,
    );
    process.exit(1);
  }
}

console.log(`Release metadata agrees on version ${expectedVersion}`);
