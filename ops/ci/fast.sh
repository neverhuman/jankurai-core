#!/usr/bin/env bash
# Deterministic fast lane: the narrowest proof loop for agent iteration.
# Identical command set is exposed locally via `just fast` and
# `bash scripts/ci-local.sh fast`.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "fast lane: locked check + nextest + fail-closed full audit"
mkdir -p target/jankurai
cargo check -p jankurai --locked --offline
cargo nextest run -p jankurai --locked --offline
cargo run -p jankurai --locked --offline -- audit . --mode advisory --full \
  --no-score-history --fail-under 85 --fail-on high \
  --json target/jankurai/audit-fast.json \
  --md target/jankurai/audit-fast.md
jq -e '
  (.score >= 85)
  and ((.caps_applied | length) == 0)
  and (.decision.hard_findings == 0)
  and (.decision.passed == true)
' target/jankurai/audit-fast.json >/dev/null
jq '{score, raw_score, caps_applied, findings, decision}' target/jankurai/audit-fast.json \
  > target/jankurai/fast-score.json

assert_artifact target/jankurai/audit-fast.json
assert_artifact target/jankurai/fast-score.json
