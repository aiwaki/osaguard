import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = dirname(scriptsDirectory);

test("stable binary release remains closed while signed preview publication is explicit", async () => {
  const [
    releaseWorkflow,
    publishWorkflow,
    previewWorkflow,
    previewUpdaterConfiguration,
    committedUpdaterKey,
    committedSigningCertificate,
    releaseGuide,
    englishReadme,
  ] = await Promise.all([
    readFile(
      join(repositoryDirectory, ".github", "workflows", "release.yml"),
      "utf8",
    ),
    readFile(
      join(repositoryDirectory, ".github", "workflows", "publish-release.yml"),
      "utf8",
    ),
    readFile(
      join(repositoryDirectory, ".github", "workflows", "preview-release.yml"),
      "utf8",
    ),
    readFile(
      join(repositoryDirectory, "scripts", "configure-preview-updater.mjs"),
      "utf8",
    ),
    readFile(
      join(repositoryDirectory, "config", "osaguard-preview-updater.pub"),
      "utf8",
    ),
    readFile(
      join(
        repositoryDirectory,
        "docs",
        "release-signing",
        "osaguard-preview-code-signing.pem",
      ),
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
  assert.match(releaseGuide, /persistent self-signed/i);
  assert.match(englishReadme, /public preview/i);

  assert.match(previewWorkflow, /workflow_dispatch/);
  assert.match(previewWorkflow, /runs-on: macos-14/);
  assert.match(previewWorkflow, /actions: read/);
  assert.match(previewWorkflow, /prerelease=true/);
  assert.match(previewWorkflow, /make_latest=false/);
  assert.match(previewWorkflow, /draft=true/);
  assert.doesNotMatch(previewWorkflow, /draft=false/);
  assert.match(previewWorkflow, /npm run build:updater/);
  assert.match(
    previewWorkflow,
    /src-tauri\/target\/aarch64-apple-darwin\/release\/bundle/,
  );
  assert.match(previewWorkflow, /actions\/attest@[0-9a-f]{40}/);
  assert.match(previewWorkflow, /persist-credentials: false/);
  assert.match(previewWorkflow, /default: "1"/);
  assert.match(previewWorkflow, /\[\[ "\$PREVIEW" == 1 \]\]/);
  assert.match(
    previewWorkflow,
    /\[\[ "\$version" == "0\.1\.3-preview\.\$\{PREVIEW\}" \]\]/,
  );
  assert.match(previewWorkflow, /echo "preview=\$PREVIEW"/);
  assert.match(
    previewWorkflow,
    /OSAGUARD_PREVIEW_SEQUENCE: \$\{\{ inputs\.preview \}\}/,
  );
  assert.match(previewWorkflow, /tag="v\$\{version\}"/);
  assert.match(previewWorkflow, /OsaGuard_\$\{RELEASE_VERSION\}_aarch64/);
  assert.doesNotMatch(previewWorkflow, /preview\.1_aarch64|\(Preview 1\)/);
  for (const secret of [
    "APPLE_CERTIFICATE",
    "APPLE_CERTIFICATE_PASSWORD",
    "TAURI_SIGNING_PRIVATE_KEY",
    "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
  ]) {
    const occurrences = previewWorkflow.match(
      new RegExp(`secrets\\.${secret}\\b`, "g"),
    );
    assert.equal(occurrences?.length, 1, `${secret} must have one narrow use`);
  }
  assert.doesNotMatch(previewWorkflow, /secrets\.APPLE_SIGNING_IDENTITY/);
  assert.doesNotMatch(previewWorkflow, /vars\.OSAGUARD_UPDATER_PUBLIC_KEY/);
  assert.match(previewWorkflow, /OsaGuard Preview Code Signing/);
  assert.match(
    previewWorkflow,
    /a6cf1f0bc828d93e7b4f0fbc87a5163968acd7499decbfb29314ecd76db92c52/,
  );
  assert.match(
    previewWorkflow,
    /894700cbb7d156943c872afab16ed609ca1f43e4/,
  );
  assert.match(previewWorkflow, /osaguard-preview-code-signing\.pem/);
  assert.match(previewWorkflow, /cmp -s "\$pinned_der" "\$imported_der"/);
  assert.ok(
    previewWorkflow.indexOf("Validate source before loading signing secrets") <
      previewWorkflow.indexOf("Import the persistent preview signing identity"),
  );
  assert.match(previewWorkflow, /security import/);
  assert.match(previewWorkflow, /security delete-keychain/);
  assert.match(previewWorkflow, /OsaGuard\.app\.tar\.gz/);
  assert.match(previewWorkflow, /latest\.json/);
  assert.match(previewWorkflow, /verify-updater-signature\.mjs/);
  assert.doesNotMatch(previewWorkflow, /notarytool|APPLE_ID|APPLE_TEAM_ID/);
  assert.match(
    previewUpdaterConfiguration,
    /config\.bundle\.macOS\.signingIdentity = signingIdentity/,
  );
  assert.match(previewUpdaterConfiguration, /osaguard-preview-updater\.pub/);
  assert.match(committedUpdaterKey.trim(), /^[A-Za-z0-9+/]+={0,2}$/);
  assert.match(committedSigningCertificate, /^-----BEGIN CERTIFICATE-----/);
});
