#!/usr/bin/env bash
# Build + test the workspace with every feature enabled.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --workspace --all-features "$@"
