#!/usr/bin/env node

import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const projectDir = dirname(scriptDir);
const workflowsDir = join(projectDir, ".github", "workflows");
const workflowFiles = (await readdir(workflowsDir))
  .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
  .sort();
const failures = [];

for (const filename of workflowFiles) {
  const contents = await readFile(join(workflowsDir, filename), "utf8");
  for (const [index, line] of contents.split(/\r?\n/).entries()) {
    const match = line.match(/^\s*(?:-\s*)?uses:\s*([^#\s]+)(?:\s+#\s*(.+))?$/);
    if (!match || match[1].startsWith("./")) {
      continue;
    }
    const reference = match[1];
    const annotation = match[2]?.trim();
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.\/-]+@[0-9a-f]{40}$/.test(reference)) {
      failures.push(`${filename}:${index + 1}: ${reference} is not pinned to a full commit SHA`);
    } else if (!annotation) {
      failures.push(`${filename}:${index + 1}: ${reference} is missing a version annotation`);
    }
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log(`Verified immutable action pins in ${workflowFiles.length} workflows`);
