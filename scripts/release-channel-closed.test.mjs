import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = dirname(scriptsDirectory);

test("stable binary release remains closed while hosted ad-hoc preview publication is explicit", async () => {
  const [releaseWorkflow, publishWorkflow, previewWorkflow, releaseGuide, englishReadme] =
    await Promise.all([
    readFile(join(repositoryDirectory, ".github", "workflows", "release.yml"), "utf8"),
    readFile(
      join(repositoryDirectory, ".github", "workflows", "publish-release.yml"),
      "utf8",
    ),
    readFile(
      join(repositoryDirectory, ".github", "workflows", "preview-release.yml"),
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

  assert.match(releaseGuide, /^## Stable channel: closed$/m);
  assert.match(releaseGuide, /^## Public preview channel$/m);
  assert.doesNotMatch(releaseGuide, /permanent self-signed/i);
  assert.match(englishReadme, /public preview/i);

  assert.match(previewWorkflow, /workflow_dispatch/);
  assert.match(previewWorkflow, /runs-on: macos-14/);
  assert.match(previewWorkflow, /prerelease=true/);
  assert.match(previewWorkflow, /make_latest=false/);
  assert.match(previewWorkflow, /npm run build:local/);
  assert.match(previewWorkflow, /actions\/attest@[0-9a-f]{40}/);
  assert.doesNotMatch(previewWorkflow, /\bsecrets\./);
  assert.doesNotMatch(previewWorkflow, /\bsecurity\b|\bnotary\b/i);
});
