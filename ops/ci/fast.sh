#!/usr/bin/env bash
# Deterministic fast lane: the narrowest proof loop for agent iteration.
# Identical command set is exposed locally via `just fast` and
# `bash scripts/ci-local.sh fast`.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "fast lane: targeted locked check + nextest + changed-scope audit"
mkdir -p target/jankurai
cargo check -p jankurai --locked
cargo nextest run -p jankurai
cargo run -p jankurai -- audit . --changed-fast --changed Cargo.lock \
  --no-score-history --json target/jankurai/audit-fast.json \
  --md target/jankurai/audit-fast.md
jq '{score, raw_score, caps_applied, findings}' target/jankurai/audit-fast.json \
  > target/jankurai/fast-score.json

assert_artifact target/jankurai/audit-fast.json
assert_artifact target/jankurai/fast-score.json
