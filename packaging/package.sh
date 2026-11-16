#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(uname -m)" in
  x86_64) target=x86_64-unknown-linux-gnu ;;
  aarch64) target=aarch64-unknown-linux-gnu ;;
  *) printf 'unsupported build architecture\n' >&2; exit 1 ;;
esac

binary=target/release/rdns
test -x "$binary"
mkdir -p release
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
cp "$binary" "$staging/rdns"
cp config.example.toml README.md "$staging/"
cp packaging/rdns.service "$staging/"
archive="release/rdns-v0.1.0-${target}.tar.gz"
tar -C "$staging" -czf "$archive" .
(cd release && sha256sum "$(basename "$archive")" > SHA256SUMS)
printf '%s\n' "$archive"
