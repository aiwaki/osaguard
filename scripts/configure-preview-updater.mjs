#!/usr/bin/env node

import { readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const signingIdentity = "OsaGuard Preview Code Signing";
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const projectDirectory = dirname(scriptDirectory);
const publicKeyPath = join(
  projectDirectory,
  "config",
  "osaguard-preview-updater.pub",
);
const encodedPublicKey = (await readFile(publicKeyPath, "utf8")).trim();
if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encodedPublicKey)) {
  throw new Error("committed updater public key is not canonical base64");
}
const decoded = Buffer.from(encodedPublicKey, "base64");
if (decoded.toString("base64") !== encodedPublicKey) {
  throw new Error("committed updater public key is not canonical base64");
}
const lines = decoded.toString("utf8").trimEnd().split(/\r?\n/);
const innerPublicKey = lines.length === 2 ? Buffer.from(lines[1], "base64") : null;
if (
  lines.length !== 2 ||
  !lines[0].startsWith("untrusted comment: ") ||
  innerPublicKey.length !== 42 ||
  innerPublicKey.toString("base64") !== lines[1] ||
  !["Ed", "ED"].includes(innerPublicKey.subarray(0, 2).toString("ascii"))
) {
  throw new Error("committed updater public key is not a Tauri minisign public key");
}

const configPath = join(
  projectDirectory,
  "app-tauri",
  "src-tauri",
  "tauri.conf.json",
);
const config = JSON.parse(await readFile(configPath, "utf8"));
if (!/^\d+\.\d+\.\d+-preview\.[1-9][0-9]*$/.test(config.version)) {
  throw new Error("preview updater configuration requires a canonical preview version");
}
config.plugins ??= {};
config.plugins.updater ??= {};
config.plugins.updater.pubkey = encodedPublicKey;
config.plugins.updater.endpoints = [];
config.bundle ??= {};
config.bundle.createUpdaterArtifacts = true;
config.bundle.macOS ??= {};
config.bundle.macOS.signingIdentity = signingIdentity;

const temporaryPath = `${configPath}.tmp`;
await writeFile(temporaryPath, `${JSON.stringify(config, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o644,
});
await rename(temporaryPath, configPath);
console.log("Configured the signed preview updater public key");
