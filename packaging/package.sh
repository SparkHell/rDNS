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
version="${RDNS_PACKAGE_VERSION:-v0.1.0}"
[[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { printf 'invalid package version\n' >&2; exit 1; }
mkdir -p release
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
cp "$binary" "$staging/rdns"
cp config.example.toml README.md LICENSE THIRD-PARTY.md "$staging/"
mkdir -p "$staging/resources"
cp resources/gfwlist.txt resources/gfwlist-LICENSE.txt "$staging/resources/"
cp packaging/rdns.service "$staging/"
archive="release/rdns-${version}-${target}.tar.gz"
tar -C "$staging" -czf "$archive" .
(cd release && sha256sum "$(basename "$archive")" > SHA256SUMS)
printf '%s\n' "$archive"
