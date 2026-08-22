#!/bin/bash
set -euo pipefail

required_environment=(
  GITHUB_ENV
  RUNNER_TEMP
  OSAGUARD_CODE_SIGNING_P12_BASE64
  OSAGUARD_CODE_SIGNING_P12_PASSWORD
  OSAGUARD_CODE_SIGNING_CERTIFICATE_SHA256
)
for name in "${required_environment[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "Missing release signing environment: $name" >&2
    exit 1
  fi
done

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

expected_fingerprint=$(printf '%s' "$OSAGUARD_CODE_SIGNING_CERTIFICATE_SHA256" | /usr/bin/tr -d ':[:space:]' | /usr/bin/tr '[:lower:]' '[:upper:]')
if [[ ! "$expected_fingerprint" =~ ^[0-9A-F]{64}$ ]]; then
  echo "OSAGUARD_CODE_SIGNING_CERTIFICATE_SHA256 must contain exactly one SHA-256 fingerprint" >&2
  exit 1
fi

umask 077
working_directory=$(/usr/bin/mktemp -d "$RUNNER_TEMP/osaguard-signing.XXXXXX")
keychain_path="$working_directory/release-signing.keychain-db"
p12_path="$working_directory/release-signing.p12"
certificate_path="$working_directory/release-signing.pem"
search_list_snapshot="$working_directory/user-search-list.before"
keychain_password=$(/usr/bin/openssl rand -hex 32)
complete=false
search_list_changed=false
recovery_required=false

emit_recovery_instructions() {
  local reason=$1
  echo "::error::${reason}. Preserved temporary signing Keychain and search-list snapshot for recovery." >&2
  echo "Temporary signing Keychain: $keychain_path" >&2
  echo "Search-list snapshot: $search_list_snapshot" >&2
  echo "Recover the user search list before deleting either file:" >&2
  echo "RUNNER_TEMP=$RUNNER_TEMP OSAGUARD_CODE_SIGNING_SEARCH_LIST_CHANGED=true OSAGUARD_CODE_SIGNING_SEARCH_LIST_SNAPSHOT=$search_list_snapshot $script_directory/restore-release-signing-keychain-search-list.sh" >&2
}

cleanup() {
  status=$?
  trap - EXIT
  /bin/rm -f -- "$p12_path" "$certificate_path"
  if [[ "$complete" != true && "$search_list_changed" == true ]]; then
    if ! OSAGUARD_CODE_SIGNING_SEARCH_LIST_CHANGED=true \
      OSAGUARD_CODE_SIGNING_SEARCH_LIST_SNAPSHOT="$search_list_snapshot" \
      "$script_directory/restore-release-signing-keychain-search-list.sh"; then
      echo "Failed to restore the original user Keychain search list" >&2
      status=1
      recovery_required=true
      emit_recovery_instructions "Could not restore the original user Keychain search list"
    fi
  fi
  if [[ "$complete" != true && "$recovery_required" != true ]]; then
    if /usr/bin/security delete-keychain "$keychain_path" >/dev/null 2>&1; then
      /bin/rm -f -- "$search_list_snapshot"
      /bin/rmdir "$working_directory" >/dev/null 2>&1 || true
    else
      status=1
      recovery_required=true
      emit_recovery_instructions "Could not delete the temporary release signing Keychain after restoration"
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

printf '%s' "$OSAGUARD_CODE_SIGNING_P12_BASE64" | /usr/bin/base64 -D > "$p12_path"
[[ -s "$p12_path" ]]

/usr/bin/security create-keychain -p "$keychain_password" "$keychain_path"
/usr/bin/security set-keychain-settings -lut 21600 "$keychain_path"
/usr/bin/security unlock-keychain -p "$keychain_password" "$keychain_path"
# `security import` offers no documented non-GUI stdin/FD passphrase interface.
# `-P` is therefore limited to this protected ephemeral release runner; see
# docs/RELEASING.md for the explicit same-runner process-argument boundary.
/usr/bin/security import "$p12_path" \
  -k "$keychain_path" \
  -P "$OSAGUARD_CODE_SIGNING_P12_PASSWORD" \
  -T /usr/bin/codesign \
  -T /usr/bin/security >/dev/null
/usr/bin/security set-key-partition-list \
  -S apple-tool:,apple: \
  -s \
  -k "$keychain_password" \
  "$keychain_path" >/dev/null 2>&1

umask 077
/usr/bin/security list-keychains -d user > "$search_list_snapshot"
[[ -s "$search_list_snapshot" && ! -L "$search_list_snapshot" ]]
[[ $(/usr/bin/stat -f '%Lp' "$search_list_snapshot") == "600" ]]
existing_keychains=()
while IFS= read -r existing_keychain; do
  [[ -n "$existing_keychain" ]] && existing_keychains+=("$existing_keychain")
done < <(
  /usr/bin/sed -n \
    -e 's/^[[:space:]]*"//' \
    -e 's/"[[:space:]]*$//' \
    -e '/^$/d' \
    "$search_list_snapshot"
)
if [[ ${#existing_keychains[@]} -eq 0 ]]; then
  echo "The existing user Keychain search list is empty; refusing to change it" >&2
  exit 1
fi
for existing_keychain in "${existing_keychains[@]}"; do
  if [[ "$existing_keychain" == *'"'* || "$existing_keychain" == *\\* ]]; then
    echo "The existing user Keychain search list contains an unsupported escaped path" >&2
    exit 1
  fi
done
/usr/bin/security list-keychains -d user -s "$keychain_path" "${existing_keychains[@]}"
search_list_changed=true

identity_listing=$(/usr/bin/security find-identity -p codesigning "$keychain_path")
if [[ $(/usr/bin/grep -Fc "\"$signing_identity\"" <<< "$identity_listing") -ne 1 ]]; then
  echo "The imported P12 does not contain exactly one '$signing_identity' code-signing identity" >&2
  exit 1
fi

/usr/bin/security find-certificate -c "$signing_identity" -p "$keychain_path" > "$certificate_path"
if [[ $(/usr/bin/grep -c '^-----BEGIN CERTIFICATE-----$' "$certificate_path") -ne 1 ]]; then
  echo "The imported identity does not resolve to exactly one certificate" >&2
  exit 1
fi
certificate_subject=$(/usr/bin/openssl x509 -in "$certificate_path" -noout -subject -nameopt RFC2253)
certificate_subject=${certificate_subject#subject=}
if [[ ",$certificate_subject," != *,CN="$signing_identity",* ]]; then
  echo "The imported certificate common name does not match the fixed release identity" >&2
  exit 1
fi
actual_fingerprint=$(/usr/bin/openssl x509 -in "$certificate_path" -noout -fingerprint -sha256)
actual_fingerprint=${actual_fingerprint#*=}
actual_fingerprint=$(printf '%s' "$actual_fingerprint" | /usr/bin/tr -d ':[:space:]' | /usr/bin/tr '[:lower:]' '[:upper:]')
if [[ "$actual_fingerprint" != "$expected_fingerprint" ]]; then
  echo "The imported code-signing certificate does not match the configured SHA-256 fingerprint" >&2
  exit 1
fi

/usr/bin/openssl x509 -in "$certificate_path" -noout -checkend 0 >/dev/null
/bin/rm -f -- "$p12_path" "$certificate_path"
{
  echo "OSAGUARD_CODE_SIGNING_KEYCHAIN=$keychain_path"
  echo "OSAGUARD_CODE_SIGNING_IDENTITY=$signing_identity"
  echo "OSAGUARD_CODE_SIGNING_SEARCH_LIST_CHANGED=true"
  echo "OSAGUARD_CODE_SIGNING_SEARCH_LIST_SNAPSHOT=$search_list_snapshot"
} >> "$GITHUB_ENV"
complete=true

echo "Imported the fixed OsaGuard release signing identity into a temporary keychain"
