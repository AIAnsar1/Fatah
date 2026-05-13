#!/usr/bin/env bash
# Run clippy over the whole workspace with warnings promoted to errors —
# the same gate CI enforces.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo clippy --workspace --all-targets --all-features -- -D warnings
