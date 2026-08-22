#!/bin/bash
set -euo pipefail

if [[ $# -ne 0 ]]; then
  echo "Usage: restore-release-signing-keychain-search-list.sh" >&2
  exit 64
fi

if [[ "${OSAGUARD_CODE_SIGNING_SEARCH_LIST_CHANGED:-}" != "true" ]]; then
  exit 0
fi

if [[ -z "${RUNNER_TEMP:-}" || -z "${OSAGUARD_CODE_SIGNING_SEARCH_LIST_SNAPSHOT:-}" ]]; then
  echo "Missing temporary-runner or signing search-list snapshot environment" >&2
  exit 1
fi

snapshot_path=$OSAGUARD_CODE_SIGNING_SEARCH_LIST_SNAPSHOT
if [[ "$snapshot_path" != "$RUNNER_TEMP"/osaguard-signing.*/user-search-list.before || \
      ! -f "$snapshot_path" || -L "$snapshot_path" ]]; then
  echo "Refusing an unexpected signing Keychain search-list snapshot path" >&2
  exit 1
fi

snapshot_mode=$(/usr/bin/stat -f '%Lp' "$snapshot_path")
if [[ "$snapshot_mode" != "600" ]]; then
  echo "Signing Keychain search-list snapshot must have mode 0600" >&2
  exit 1
fi

keychains=()
while IFS= read -r keychain; do
  [[ -n "$keychain" ]] && keychains+=("$keychain")
done < <(
  /usr/bin/sed -n \
    -e 's/^[[:space:]]*"//' \
    -e 's/"[[:space:]]*$//' \
    -e '/^$/d' \
    "$snapshot_path"
)

for keychain in "${keychains[@]}"; do
  if [[ "$keychain" == *'"'* || "$keychain" == *\\* ]]; then
    echo "Signing Keychain search-list snapshot contains an unsupported escaped path" >&2
    exit 1
  fi
done

if [[ ${#keychains[@]} -eq 0 ]]; then
  # The `security` CLI documents the keychain arguments to `-s` as optional;
  # this restores the valid empty user search list used by fresh runners.
  /usr/bin/security list-keychains -d user -s
else
  /usr/bin/security list-keychains -d user -s "${keychains[@]}"
fi

restored_keychains=()
while IFS= read -r keychain; do
  [[ -n "$keychain" ]] && restored_keychains+=("$keychain")
done < <(
  /usr/bin/security list-keychains -d user | /usr/bin/sed -n \
    -e 's/^[[:space:]]*"//' \
    -e 's/"[[:space:]]*$//' \
    -e '/^$/d'
)

if [[ ${#restored_keychains[@]} -ne ${#keychains[@]} ]]; then
  echo "Signing Keychain search list did not restore to the saved length" >&2
  exit 1
fi
for index in "${!keychains[@]}"; do
  if [[ "${restored_keychains[$index]}" != "${keychains[$index]}" ]]; then
    echo "Signing Keychain search list did not restore exactly" >&2
    exit 1
  fi
done

echo "Restored the original user Keychain search list"
