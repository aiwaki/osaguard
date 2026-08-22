#!/usr/bin/env node

import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [archivePath, signaturePath, publicKeyArgument] = process.argv.slice(2);
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const committedPublicKeyPath = join(
  dirname(scriptDirectory),
  "config",
  "osaguard-preview-updater.pub",
);
const publicKeyPath = publicKeyArgument
  ? resolve(publicKeyArgument)
  : committedPublicKeyPath;

if (!archivePath || !signaturePath) {
  console.error(
    "Usage: verify-updater-signature.mjs <archive> <signature-file> [public-key-file]",
  );
  process.exit(1);
}
const encodedPublicKey = (await readFile(publicKeyPath, "utf8")).trim();

function decodeOuterBase64(encoded, label) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new Error(`${label} is not canonical base64`);
  }
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.toString("base64") !== encoded) {
    throw new Error(`${label} is not canonical base64`);
  }
  return decoded.toString("utf8");
}

function decodeInnerBase64(encoded, expectedLength, label) {
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.length !== expectedLength || decoded.toString("base64") !== encoded) {
    throw new Error(`${label} has invalid encoding or length`);
  }
  return decoded;
}

function publicKeyFromTauri(encoded) {
  const lines = decodeOuterBase64(encoded, "updater public key")
    .trimEnd()
    .split(/\r?\n/);
  if (lines.length !== 2 || !lines[0].startsWith("untrusted comment: ")) {
    throw new Error("updater public key has invalid minisign framing");
  }
  const decoded = decodeInnerBase64(lines[1], 42, "updater public key");
  const algorithm = decoded.subarray(0, 2).toString("ascii");
  if (algorithm !== "Ed" && algorithm !== "ED") {
    throw new Error("updater public key uses an unsupported algorithm");
  }
  const keyId = decoded.subarray(2, 10);
  const rawKey = decoded.subarray(10);
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const key = createPublicKey({
    key: Buffer.concat([spkiPrefix, rawKey]),
    format: "der",
    type: "spki",
  });
  return { key, keyId };
}

function signatureFromTauri(encoded) {
  const lines = decodeOuterBase64(encoded, "updater signature")
    .trimEnd()
    .split(/\r?\n/);
  if (
    lines.length !== 4 ||
    !lines[0].startsWith("untrusted comment: ") ||
    !lines[2].startsWith("trusted comment: ")
  ) {
    throw new Error("updater signature has invalid minisign framing");
  }
  const decoded = decodeInnerBase64(lines[1], 74, "updater signature");
  if (decoded.subarray(0, 2).toString("ascii") !== "ED") {
    throw new Error("updater signature must use prehashed minisign mode");
  }
  return {
    keyId: decoded.subarray(2, 10),
    signature: decoded.subarray(10),
    trustedComment: lines[2].slice("trusted comment: ".length),
    globalSignature: decodeInnerBase64(
      lines[3],
      64,
      "updater global signature",
    ),
  };
}

const { key, keyId } = publicKeyFromTauri(encodedPublicKey);
const encodedSignature = (await readFile(signaturePath, "utf8")).trim();
const signature = signatureFromTauri(encodedSignature);

if (!timingSafeEqual(keyId, signature.keyId)) {
  throw new Error("updater signature was created by a different key");
}

const hasher = createHash("blake2b512");
for await (const chunk of createReadStream(archivePath)) {
  hasher.update(chunk);
}
const digest = hasher.digest();

if (!verify(null, digest, key, signature.signature)) {
  throw new Error("updater archive signature verification failed");
}

const globalMessage = Buffer.concat([
  signature.signature,
  Buffer.from(signature.trustedComment, "utf8"),
]);
if (!verify(null, globalMessage, key, signature.globalSignature)) {
  throw new Error("updater trusted-comment signature verification failed");
}

console.log(`Verified Tauri updater signature for ${archivePath}`);
