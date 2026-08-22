#!/usr/bin/env bash
# Generate OsaGuard's permanent release credentials without accessing macOS
# Keychain services. The output directory is deliberately outside the source
# checkout so it cannot accidentally be committed.
set -euo pipefail

readonly identity_name='OsaGuard Release Code Signing'

usage() {
  echo "Usage: $0 /absolute/path/to/new-release-credentials-directory" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 64
fi

output_directory=$1
if [[ "$output_directory" != /* || "$output_directory" == / || -e "$output_directory" ]]; then
  echo "Output directory must be a new, non-root absolute path." >&2
  exit 64
fi

output_parent=$(dirname -- "$output_directory")
output_name=$(basename -- "$output_directory")
if [[ ! -d "$output_parent" || "$output_name" == . || "$output_name" == .. ]]; then
  echo "The output directory's parent must already exist." >&2
  exit 64
fi
output_parent=$(CDPATH= cd -- "$output_parent" && pwd -P)
output_directory="$output_parent/$output_name"

script_directory=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_directory=$(dirname -- "$script_directory")
tauri_binary="$project_directory/app-tauri/node_modules/.bin/tauri"

for command in openssl mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Missing required command: $command" >&2
    exit 69
  }
done
if [[ ! -x "$tauri_binary" ]]; then
  echo "Tauri CLI is not installed. Run npm ci in app-tauri first." >&2
  exit 69
fi

temporary_directory=$(mktemp -d "$output_parent/.osaguard-release-bootstrap.XXXXXX")
cleanup() {
  if [[ -n "${temporary_directory:-}" && -d "$temporary_directory" ]]; then
    rm -rf -- "$temporary_directory"
  fi
}
trap cleanup EXIT HUP INT TERM
chmod 700 "$temporary_directory"

openssl rand -base64 48 | tr -d '\n' > "$temporary_directory/code-signing-p12-password"
openssl rand -base64 48 | tr -d '\n' > "$temporary_directory/tauri-updater-key-password"
chmod 600 "$temporary_directory"/*-password

cat > "$temporary_directory/code-signing-openssl.cnf" <<'EOF'
[req]
distinguished_name = subject
x509_extensions = code_signing
prompt = no

[subject]
CN = OsaGuard Release Code Signing

[code_signing]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 \
  -keyout "$temporary_directory/.code-signing.key" \
  -out "$temporary_directory/code-signing-certificate.pem" \
  -config "$temporary_directory/code-signing-openssl.cnf" >/dev/null 2>&1
openssl pkcs12 -export -legacy \
  -out "$temporary_directory/osaguard-release-signing.p12" \
  -inkey "$temporary_directory/.code-signing.key" \
  -in "$temporary_directory/code-signing-certificate.pem" \
  -name "$identity_name" \
  -passout "file:$temporary_directory/code-signing-p12-password"
openssl x509 -in "$temporary_directory/code-signing-certificate.pem" -noout -fingerprint -sha256 \
  | sed 's/^.*=//' | tr -d ':' > "$temporary_directory/code-signing-certificate-sha256"

updater_password=$(< "$temporary_directory/tauri-updater-key-password")
"$tauri_binary" signer generate --ci \
  --write-keys "$temporary_directory/tauri-updater.key" \
  --password "$updater_password" > "$temporary_directory/tauri-signer.log"
unset updater_password
[[ -s "$temporary_directory/tauri-updater.key" && -s "$temporary_directory/tauri-updater.key.pub" ]]

{
  printf 'OSAGUARD_UPDATER_PUBLIC_KEY='
  tr -d '\n' < "$temporary_directory/tauri-updater.key.pub"
  printf '\nOSAGUARD_CODE_SIGNING_CERTIFICATE_SHA256='
  tr -d '\n' < "$temporary_directory/code-signing-certificate-sha256"
  printf '\n'
} > "$temporary_directory/github-public-values.env"

rm -f -- \
  "$temporary_directory/.code-signing.key" \
  "$temporary_directory/code-signing-openssl.cnf" \
  "$temporary_directory/tauri-signer.log"
find "$temporary_directory" -type f -exec chmod 600 {} +
mv -- "$temporary_directory" "$output_directory"
temporary_directory=''

echo "Created OsaGuard release credentials in: $output_directory"
echo "Keep this directory backed up and outside every source checkout."
echo "The GitHub public values are in: $output_directory/github-public-values.env"
