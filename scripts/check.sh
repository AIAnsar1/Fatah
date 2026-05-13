#!/usr/bin/env bash
# Fast pre-commit pipeline: fmt-check, clippy, test. Bails on first
# failure so locally you can iterate on what broke without scrolling.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> rustfmt --check"
cargo fmt --all --check

echo "==> clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> tests"
cargo test --workspace --all-features

echo "all green."
