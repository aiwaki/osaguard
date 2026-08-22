#!/usr/bin/env node

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const supportedTargets = new Set([
  "aarch64-apple-darwin",
  "x86_64-apple-darwin",
  "universal-apple-darwin",
]);
const target = process.argv[2];

if (!supportedTargets.has(target)) {
  console.error(
    "Usage: generate-release-config.mjs <aarch64-apple-darwin|x86_64-apple-darwin|universal-apple-darwin>",
  );
  process.exit(1);
}

const requiredEnvironment = ["OSAGUARD_UPDATER_PUBLIC_KEY"];
const missing = requiredEnvironment.filter(
  (name) => !process.env[name] || process.env[name].trim().length === 0,
);

if (missing.length > 0) {
  console.error(`Missing release environment: ${missing.join(", ")}`);
  process.exit(1);
}

const updaterPublicKey = process.env.OSAGUARD_UPDATER_PUBLIC_KEY.trim();

const scriptDir = dirname(fileURLToPath(import.meta.url));
const projectDir = dirname(scriptDir);
const signingConfig = JSON.parse(
  await readFile(join(scriptDir, "release-signing.json"), "utf8"),
);
if (
  signingConfig.model !== "self-signed-certificate" ||
  typeof signingConfig.identity !== "string" ||
  signingConfig.identity.trim() !== signingConfig.identity ||
  signingConfig.identity.length === 0 ||
  signingConfig.applicationIdentifier !== "dev.aiwaki.osaguard"
) {
  throw new Error("Release signing configuration is invalid");
}
const configuredRepository = new URL(
  JSON.parse(
    await readFile(join(projectDir, "app-tauri", "package.json"), "utf8"),
  ).homepage,
);
if (
  configuredRepository.protocol !== "https:" ||
  configuredRepository.hostname !== "github.com" ||
  configuredRepository.pathname.replace(/\/$/, "") !== "/aiwaki/osaguard"
) {
  throw new Error("Release homepage must target github.com/aiwaki/osaguard");
}
const generatedDir = join(projectDir, "app-tauri", "src-tauri", "gen");
const output = join(generatedDir, `tauri.release.${target}.conf.json`);
const temporaryOutput = `${output}.tmp`;
const releaseConfig = {
  bundle: {
    targets: ["app", "dmg"],
    createUpdaterArtifacts: true,
    macOS: {
      hardenedRuntime: true,
      signingIdentity: signingConfig.identity,
    },
  },
  plugins: {
    updater: {
      pubkey: updaterPublicKey,
      endpoints: [
        "https://github.com/aiwaki/osaguard/releases/latest/download/latest.json",
      ],
    },
  },
};

await mkdir(generatedDir, { recursive: true });
await writeFile(temporaryOutput, `${JSON.stringify(releaseConfig, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o600,
});
await rename(temporaryOutput, output);

console.log(`Generated release configuration for ${target}`);
