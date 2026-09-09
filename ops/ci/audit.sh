#!/usr/bin/env bash
# Jankurai self-audit lane: writes the repo-score artifacts that CI uploads.
# The same lane runs locally via `just audit`.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

mkdir -p .jankurai
log "audit lane: exact-source full audit -> .jankurai/repo-score.{json,md}"
cargo run --locked --offline -p jankurai -- audit . \
  --full \
  --baseline agent/baselines/main.repo-score.json \
  --no-score-history \
  --fail-under 85 \
  --fail-on high \
  --json .jankurai/repo-score.json \
  --md .jankurai/repo-score.md

jq -e --slurpfile baseline agent/baselines/main.repo-score.json '
  .score >= ($baseline[0].score)
  and .raw_score >= ($baseline[0].raw_score)
  and ((.caps_applied | length) == 0)
  and (.decision.hard_findings == 0)
  and (.decision.passed == true)
' .jankurai/repo-score.json >/dev/null

assert_artifact .jankurai/repo-score.json
assert_artifact .jankurai/repo-score.md

if [[ -f agent/badge.toml ]]; then
  log "audit lane: jankurai badge --check"
  grep -q 'jankurai-badge:start' README.md
  test -s agent/jankurai-badge.svg
  test -s agent/jankurai-badge.json
  cargo run --locked --offline -p jankurai -- badge --check \
    --score agent/baselines/main.repo-score.json \
    --out agent/jankurai-badge.svg \
    --json-out agent/jankurai-badge.json \
    --readme README.md \
    --link agent/jankurai-badge.json \
    --update-readme \
    --label jankurai
fi
