#!/usr/bin/env bash
# Deterministic fast lane: the narrowest proof loop for agent iteration.
# Identical command set is exposed locally via `just fast` and
# `bash scripts/ci-local.sh fast`.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "fast lane: cargo check + nextest"
cargo check --workspace --locked
cargo nextest run --workspace
