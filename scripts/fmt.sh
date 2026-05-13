#!/usr/bin/env bash
# Format the entire workspace in-place. Use `--check` to dry-run.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all "$@"
