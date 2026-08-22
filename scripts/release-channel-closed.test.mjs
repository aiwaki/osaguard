import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = dirname(scriptsDirectory);

test("stable binary release and publication remain fail-closed without Apple credentials", async () => {
  const [releaseWorkflow, publishWorkflow, releaseGuide, englishReadme] =
    await Promise.all([
    readFile(join(repositoryDirectory, ".github", "workflows", "release.yml"), "utf8"),
    readFile(
      join(repositoryDirectory, ".github", "workflows", "publish-release.yml"),
      "utf8",
    ),
    readFile(join(repositoryDirectory, "docs", "RELEASING.md"), "utf8"),
    readFile(join(repositoryDirectory, "README.en.md"), "utf8"),
  ]);

  for (const workflow of [releaseWorkflow, publishWorkflow]) {
    assert.match(workflow, /Stable (?:binary )?(?:release publication|publication) is disabled/i);
    assert.match(workflow, /exit 1/);
    assert.doesNotMatch(workflow, /\bsecrets\./);
    assert.doesNotMatch(workflow, /\bsecurity\b|\bcodesign\b|\bnotary\b/i);
    assert.doesNotMatch(workflow, /gh release|draft=false|make_latest=true/);
  }

  assert.match(releaseGuide, /^## Public-app release gate: closed$/m);
  assert.match(releaseGuide, /there must be \*\*no\*\* public\s+OsaGuard DMG/i);
  assert.doesNotMatch(releaseGuide, /Public OsaGuard releases use one permanent self-signed/i);
  assert.match(englishReadme, /there is no public end-user app yet/i);
  assert.doesNotMatch(englishReadme, /Download the DMG for your Mac from the/i);
});
