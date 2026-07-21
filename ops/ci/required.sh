#!/usr/bin/env bash
# Required lane: the exact mapped source proof required on every push.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "required lane: locked metadata, format, lint, and mapped fast proof"
cargo metadata --locked --offline --no-deps --format-version 1 >/dev/null
cargo fmt --all --check
cargo clippy -p jankurai --all-targets --locked --offline -- -D warnings
bash ops/ci/fast.sh
