import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const capabilityUrl = new URL(
  "../app-tauri/src-tauri/capabilities/main-window.json",
  import.meta.url,
);

test("the dashboard has only the Tauri event permissions it uses", async () => {
  const capability = JSON.parse(await readFile(capabilityUrl, "utf8"));

  assert.deepEqual(capability.windows, ["main"]);
  assert.deepEqual(capability.permissions, [
    "core:event:allow-listen",
    "core:event:allow-unlisten",
  ]);
});
