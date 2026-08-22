import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = dirname(scriptsDirectory);

test("release qualification leaves a draft and publication is separately acknowledged", async () => {
  const [releaseWorkflow, publishWorkflow, releaseGuide] = await Promise.all([
    readFile(join(repositoryDirectory, ".github", "workflows", "release.yml"), "utf8"),
    readFile(
      join(repositoryDirectory, ".github", "workflows", "publish-release.yml"),
      "utf8",
    ),
    readFile(join(repositoryDirectory, "docs", "RELEASING.md"), "utf8"),
  ]);

  const verifyJob = releaseWorkflow.slice(
    releaseWorkflow.indexOf("  verify:"),
    releaseWorkflow.indexOf("  prepare-release:"),
  );
  const buildJob = releaseWorkflow.slice(
    releaseWorkflow.indexOf("  build:"),
    releaseWorkflow.indexOf("  qualify-release:"),
  );

  assert.match(releaseWorkflow, /qualify-release:\n\s+name: Qualify release draft/);
  assert.match(releaseWorkflow, /Record verified draft handoff/);
  assert.doesNotMatch(releaseWorkflow, /-F draft=false/);
  assert.doesNotMatch(releaseWorkflow, /make_latest=true/);
  assert.match(verifyJob, /vars\.OSAGUARD_UPDATER_PUBLIC_KEY/);
  assert.doesNotMatch(verifyJob, /TAURI_SIGNING_PRIVATE_KEY/);
  assert.doesNotMatch(verifyJob, /OSAGUARD_CODE_SIGNING_P12/);
  assert.match(buildJob, /environment: release/);
  assert.match(buildJob, /secrets\.TAURI_SIGNING_PRIVATE_KEY/);
  assert.match(buildJob, /secrets\.OSAGUARD_CODE_SIGNING_P12_BASE64/);
  assert.match(buildJob, /vars\.OSAGUARD_UPDATER_PUBLIC_KEY/);

  assert.match(publishWorkflow, /^name: Publish qualified release$/m);
  assert.match(publishWorkflow, /workflow_dispatch:/);
  assert.match(publishWorkflow, /publish_acknowledgement:/);
  assert.match(publishWorkflow, /PUBLISH \$RELEASE_TAG/);
  assert.match(publishWorkflow, /environment: release/);
  assert.match(publishWorkflow, /git merge-base --is-ancestor/);
  assert.match(publishWorkflow, /SHA256SUMS does not cover exactly/);
  assert.match(publishWorkflow, /shasum -a 256 -c SHA256SUMS/);
  assert.match(publishWorkflow, /qualify-release-artifacts\.sh/);
  assert.match(publishWorkflow, /-F draft=false/);
  assert.match(publishWorkflow, /make_latest=true/);
  assert.match(publishWorkflow, /actions\/checkout@[0-9a-f]{40}/);
  assert.match(publishWorkflow, /actions\/setup-node@[0-9a-f]{40}/);

  assert.match(releaseGuide, /Publish qualified release/);
  assert.match(releaseGuide, /required reviewer/);
  assert.match(releaseGuide, /OSAGUARD_UPDATER_PUBLIC_KEY/);
});
