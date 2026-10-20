#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
bun run build:ui
cargo build --release -p app
TARGET_DIR=$(cargo metadata --no-deps --format-version 1 | jq -r '.target_directory')
HOST_TRIPLE=$(rustc -vV | sed -n 's/^host: //p')
mkdir -p src-tauri/binaries
cp "$TARGET_DIR/release/dopbase" "src-tauri/binaries/dopbase-$HOST_TRIPLE"
