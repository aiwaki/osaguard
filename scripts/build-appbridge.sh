#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <aarch64-apple-darwin|x86_64-apple-darwin> <output-directory>" >&2
  exit 2
fi

target=$1
output=$2
case "$target" in
  aarch64-apple-darwin)
    goarch=arm64
    clang_arch=arm64
    ;;
  x86_64-apple-darwin)
    goarch=amd64
    clang_arch=x86_64
    ;;
  *)
    echo "unsupported app bridge target: $target" >&2
    exit 2
    ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
mkdir -p "$output"
output_dir=$(CDPATH='' cd -- "$output" && pwd)
archive="$output_dir/libosaguard_appbridge.a"
sdk_path=$(xcrun --sdk macosx --show-sdk-path)

cd "$repo_dir"
GOOS=darwin \
GOARCH="$goarch" \
CGO_ENABLED=1 \
CC="$(xcrun -f clang) -arch $clang_arch -isysroot $sdk_path" \
CXX="$(xcrun -f clang++) -arch $clang_arch -isysroot $sdk_path" \
CGO_CFLAGS="-arch $clang_arch -isysroot $sdk_path" \
CGO_CXXFLAGS="-arch $clang_arch -isysroot $sdk_path" \
CGO_LDFLAGS="-arch $clang_arch -isysroot $sdk_path" \
go build -trimpath -buildmode=c-archive -o "$archive" ./cmd/osaguard-appbridge

mv "$output_dir/libosaguard_appbridge.h" "$output_dir/osaguard_appbridge.h"
lipo "$archive" -verify_arch "$clang_arch"
