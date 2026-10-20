#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
bun run typecheck:ui
cargo test -p app --all-targets --all-features
cargo clippy -p app -p dopbase-desktop --all-targets --all-features -- -D warnings
