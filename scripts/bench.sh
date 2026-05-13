#!/usr/bin/env bash
# Run the criterion bench suite. Pass extra args after `--`, e.g.:
#   ./scripts/bench.sh -- --save-baseline before
set -euo pipefail
cd "$(dirname "$0")/.."
cargo bench -p fatah-benchmarks "$@"
