#!/bin/bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: OSAGUARD_UPDATER_PUBLIC_KEY=... OSAGUARD_CODE_SIGNING_CERTIFICATE_SHA256=... qualify-release-artifacts.sh <assets-directory> <vVERSION> <owner/repository>" >&2
  exit 64
fi

assets_directory=$1
release_tag=$2
repository=$3
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
signing_config="$script_directory/release-signing.json"
signing_identity=$(/usr/bin/env node -e '
  const fs = require("node:fs");
  const config = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (config.model !== "self-signed-certificate" || typeof config.identity !== "string" || !config.identity) {
    process.exit(1);
  }
  process.stdout.write(config.identity);
' "$signing_config")
application_identifier=$(/usr/bin/env node -e '
  const fs = require("node:fs");
  const config = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (typeof config.applicationIdentifier !== "string" || !config.applicationIdentifier) {
    process.exit(1);
  }
  process.stdout.write(config.applicationIdentifier);
' "$signing_config")
expected_certificate_sha256=$(printf '%s' "${OSAGUARD_CODE_SIGNING_CERTIFICATE_SHA256:-}" | /usr/bin/tr -d ':[:space:]' | /usr/bin/tr '[:lower:]' '[:upper:]')

if [[ ! -d "$assets_directory" || -z "${OSAGUARD_UPDATER_PUBLIC_KEY:-}" || ! "$expected_certificate_sha256" =~ ^[0-9A-F]{64}$ ]]; then
  echo "Release assets, updater public key, and the exact release certificate SHA-256 fingerprint are required" >&2
  exit 1
fi

temporary_directory=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/osaguard-release.XXXXXX")
mounted_images=()
certificate_probe_index=0
arm64_app_cdhash=""
arm64_app_code_directory=""
arm64_app_sha256=""
arm64_app_certificate_sha256=""
arm64_app_designated_requirement=""
x86_64_app_cdhash=""
x86_64_app_code_directory=""
x86_64_app_sha256=""
x86_64_app_certificate_sha256=""
x86_64_app_designated_requirement=""

cleanup() {
  local mount_point
  for mount_point in "${mounted_images[@]:-}"; do
    if /sbin/mount | /usr/bin/grep -Fq " on ${mount_point} ("; then
      /usr/bin/hdiutil detach "$mount_point" -quiet || true
    fi
  done
  /bin/rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

require_exact_architecture() {
  local executable=$1
  local expected_architecture=$2
  local actual_architecture
  actual_architecture=$(/usr/bin/lipo -archs "$executable")
  if [[ "$actual_architecture" != "$expected_architecture" ]]; then
    echo "$executable has architecture '$actual_architecture'; expected '$expected_architecture'" >&2
    return 1
  fi
}

verify_release_signature_details() {
  local signing_details=$1
  local source_label=$2
  if /usr/bin/grep -Fq 'Signature=adhoc' <<< "$signing_details" || \
      /usr/bin/grep -Eq 'flags=.*adhoc' <<< "$signing_details"; then
    echo "$source_label is ad-hoc signed" >&2
    return 1
  fi
  if [[ $(/usr/bin/grep -Fxc "Authority=$signing_identity" <<< "$signing_details") -ne 1 ]]; then
    echo "$source_label does not have the fixed release signing authority" >&2
    return 1
  fi
  if ! /usr/bin/grep -Eq 'flags=.*\(.*runtime.*\)' <<< "$signing_details"; then
    echo "$source_label is missing hardened runtime" >&2
    return 1
  fi
}

record_application_identity() {
  local architecture=$1
  local binary=$2
  local signed_path=$3
  local signing_details=$4
  local source_label=$5
  local prefix cdhash code_directory sha256 certificate_prefix certificate_sha256
  local requirements designated_requirement requirement_count
  local cdhash_variable code_directory_variable sha256_variable
  local certificate_variable requirement_variable

  cdhash=$(/usr/bin/awk -F= '/^CDHash=/{print $2; exit}' <<< "$signing_details")
  code_directory=$(/usr/bin/awk '/^CodeDirectory /{print; exit}' <<< "$signing_details")
  sha256=$(/usr/bin/shasum -a 256 "$binary" | /usr/bin/awk '{print $1}')
  [[ "$cdhash" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]
  [[ "$code_directory" == CodeDirectory\ * ]]
  [[ "$sha256" =~ ^[0-9a-f]{64}$ ]]

  certificate_probe_index=$((certificate_probe_index + 1))
  certificate_prefix="$temporary_directory/certificate-${certificate_probe_index}-"
  /usr/bin/codesign --display --extract-certificates "$certificate_prefix" "$signed_path" >/dev/null 2>&1
  [[ -s "${certificate_prefix}0" && ! -e "${certificate_prefix}1" ]] || {
    echo "$source_label does not have exactly one self-signed certificate" >&2
    return 1
  }
  certificate_sha256=$(/usr/bin/openssl x509 -inform DER -in "${certificate_prefix}0" -noout -fingerprint -sha256)
  certificate_sha256=${certificate_sha256#*=}
  certificate_sha256=$(printf '%s' "$certificate_sha256" | /usr/bin/tr -d ':[:space:]' | /usr/bin/tr '[:lower:]' '[:upper:]')
  if [[ "$certificate_sha256" != "$expected_certificate_sha256" ]]; then
    echo "$source_label was signed by an unexpected certificate" >&2
    return 1
  fi

  requirements=$(/usr/bin/codesign --display --requirements - "$signed_path" 2>&1)
  designated_requirement=$(printf '%s\n' "$requirements" | /usr/bin/sed -nE 's/^#?[[:space:]]*(designated =>.*)$/\1/p')
  requirement_count=$(printf '%s\n' "$designated_requirement" | /usr/bin/awk 'NF { count++ } END { print count + 0 }')
  if [[ "$requirement_count" -ne 1 || "$designated_requirement" != designated\ =\>* || \
        "$designated_requirement" != *"identifier "* || \
        ( "$designated_requirement" != *"anchor "* && "$designated_requirement" != *"certificate "* ) || \
        "$designated_requirement" == *"cdhash"* ]]; then
    echo "$source_label does not have one stable certificate-and-identifier designated requirement" >&2
    return 1
  fi

  case "$architecture" in
    arm64) prefix=arm64_app ;;
    x86_64) prefix=x86_64_app ;;
    *)
      echo "Unsupported application architecture $architecture" >&2
      return 1
      ;;
  esac

  cdhash_variable="${prefix}_cdhash"
  code_directory_variable="${prefix}_code_directory"
  sha256_variable="${prefix}_sha256"
  certificate_variable="${prefix}_certificate_sha256"
  requirement_variable="${prefix}_designated_requirement"
  if [[ -z "${!cdhash_variable}" ]]; then
    printf -v "$cdhash_variable" '%s' "$cdhash"
    printf -v "$code_directory_variable" '%s' "$code_directory"
    printf -v "$sha256_variable" '%s' "$sha256"
    printf -v "$certificate_variable" '%s' "$certificate_sha256"
    printf -v "$requirement_variable" '%s' "$designated_requirement"
    return
  fi

  if [[ "${!cdhash_variable}" != "$cdhash" || \
        "${!code_directory_variable}" != "$code_directory" || \
        "${!sha256_variable}" != "$sha256" || \
        "${!certificate_variable}" != "$certificate_sha256" || \
        "${!requirement_variable}" != "$designated_requirement" ]]; then
    echo "$source_label has a different application code identity than its updater/DMG counterpart" >&2
    return 1
  fi
}

qualify_application() {
  local application=$1
  local expected_architecture=$2
  local source_label=$3
  local signing_details bundle_identifier bundle_version bundle_build_version ls_ui_element unexpected_macos_entry

  [[ -d "$application" ]] || {
    echo "$source_label does not contain OsaGuard.app" >&2
    return 1
  }

  /usr/bin/codesign --verify --deep --strict --verbose=2 "$application"
  signing_details=$(/usr/bin/codesign -dv --verbose=4 "$application" 2>&1)
  /usr/bin/grep -Fq "Identifier=$application_identifier" <<< "$signing_details"
  verify_release_signature_details "$signing_details" "$source_label application"

  bundle_identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$application/Contents/Info.plist")
  bundle_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$application/Contents/Info.plist")
  bundle_build_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$application/Contents/Info.plist")
  ls_ui_element=$(/usr/libexec/PlistBuddy -c 'Print :LSUIElement' "$application/Contents/Info.plist")
  [[ "$bundle_identifier" == "$application_identifier" ]]
  [[ "v${bundle_version}" == "$release_tag" ]]
  [[ "v${bundle_build_version}" == "$release_tag" ]]
  [[ "$ls_ui_element" == "true" ]]

  unexpected_macos_entry=$(/usr/bin/find "$application/Contents/MacOS" \
    -mindepth 1 -maxdepth 1 ! -name osaguard-tray -print -quit)
  if [[ -n "$unexpected_macos_entry" ]]; then
    echo "$source_label contains an unexpected Contents/MacOS entry: $unexpected_macos_entry" >&2
    return 1
  fi
  [[ -f "$application/Contents/MacOS/osaguard-tray" && -x "$application/Contents/MacOS/osaguard-tray" ]]
  require_exact_architecture "$application/Contents/MacOS/osaguard-tray" "$expected_architecture"
  record_application_identity \
    "$expected_architecture" \
    "$application/Contents/MacOS/osaguard-tray" \
    "$application" \
    "$signing_details" \
    "$source_label"
}

updater_rows=()
while IFS= read -r updater_row; do
  updater_rows+=("$updater_row")
done < <(
  /usr/bin/env node "$script_directory/validate-release-assets.mjs" \
    "$assets_directory" "$release_tag" "$repository"
)

if [[ ${#updater_rows[@]} -ne 2 ]]; then
  echo "Updater metadata did not yield exactly two macOS artifacts" >&2
  exit 1
fi

for row in "${updater_rows[@]}"; do
  IFS=$'\t' read -r platform architecture archive <<< "$row"
  /usr/bin/env node "$script_directory/verify-updater-signature.mjs" \
    "$archive" "${archive}.sig"
  extraction_directory="$temporary_directory/${platform}-updater"
  /bin/mkdir -p "$extraction_directory"
  /usr/bin/tar -xzf "$archive" -C "$extraction_directory"
  application=$(/usr/bin/find "$extraction_directory" -maxdepth 2 -type d -name OsaGuard.app -print -quit)
  qualify_application "$application" "$architecture" "$platform updater archive"
done

shopt -s nullglob
apple_silicon_images=("$assets_directory"/*_aarch64.dmg)
intel_images=("$assets_directory"/*_x64.dmg)
shopt -u nullglob

if [[ ${#apple_silicon_images[@]} -ne 1 || ${#intel_images[@]} -ne 1 ]]; then
  echo "Expected one Apple Silicon DMG and one Intel DMG" >&2
  exit 1
fi

for architecture_and_image in \
  "arm64:${apple_silicon_images[0]}" \
  "x86_64:${intel_images[0]}"; do
  architecture=${architecture_and_image%%:*}
  disk_image=${architecture_and_image#*:}
  mount_point="$temporary_directory/mount-${architecture}"
  /bin/mkdir -p "$mount_point"

  /usr/bin/hdiutil attach "$disk_image" -readonly -nobrowse -mountpoint "$mount_point" -quiet
  mounted_images+=("$mount_point")
  qualify_application "$mount_point/OsaGuard.app" "$architecture" "$(basename "$disk_image")"
  /usr/bin/hdiutil detach "$mount_point" -quiet
done

for certificate_sha256 in \
  "$arm64_app_certificate_sha256" \
  "$x86_64_app_certificate_sha256"; do
  if [[ "$certificate_sha256" != "$expected_certificate_sha256" ]]; then
    echo "A qualified component lost the fixed release certificate" >&2
    exit 1
  fi
done

if [[ "$arm64_app_designated_requirement" != "$x86_64_app_designated_requirement" ]]; then
  echo "The two architectures have different application designated requirements" >&2
  exit 1
fi

identity_manifest="$assets_directory/CODE_IDENTITIES.txt"
identity_manifest_temporary="${identity_manifest}.tmp"
{
  echo "OsaGuard release code identities"
  echo "release_tag=$release_tag"
  echo "signing_model=self-signed-certificate"
  echo "signing_identity=$signing_identity"
  echo "certificate_sha256=$expected_certificate_sha256"
  echo "app.designated_requirement=$arm64_app_designated_requirement"
  echo "darwin-aarch64.osaguard-tray.sha256=$arm64_app_sha256"
  echo "darwin-aarch64.osaguard-tray.cdhash=$arm64_app_cdhash"
  echo "darwin-aarch64.osaguard-tray.code_directory=$arm64_app_code_directory"
  echo "darwin-x86_64.osaguard-tray.sha256=$x86_64_app_sha256"
  echo "darwin-x86_64.osaguard-tray.cdhash=$x86_64_app_cdhash"
  echo "darwin-x86_64.osaguard-tray.code_directory=$x86_64_app_code_directory"
} > "$identity_manifest_temporary"
/bin/mv -f -- "$identity_manifest_temporary" "$identity_manifest"

echo "Qualified both OsaGuard macOS architectures and updater metadata"
