#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
npm --prefix web ci --no-audit --no-fund
npm --prefix web run build
cargo build --release --locked --bin rdns "$@"
