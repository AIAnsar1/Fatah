#!/usr/bin/env bash
# Produce a stripped release binary at dist/fatah.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p dist
cargo build --release -p fatah-cli
cp target/release/fatah dist/fatah
echo "==> dist/fatah ($(du -h dist/fatah | cut -f1))"
