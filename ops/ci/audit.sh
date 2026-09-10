#!/usr/bin/env bash
# Jankurai self-audit lane: writes the repo-score artifacts that CI uploads.
# The same lane runs locally via `just audit`.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

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

mkdir -p .jankurai target/jankurai
# Select the executable Cargo actually built, including custom target paths.
# Invoke those bytes directly and retain their digest before running the audit.
cargo build --locked --offline -p jankurai --bin jankurai --message-format=json \
  > target/jankurai/auditor-build.jsonl
auditor="$(jq -ser '
  [.[] | select(.reason == "compiler-artifact" and .target.name == "jankurai"
    and .target.kind == ["bin"] and .executable != null) | .executable]
  | if length == 1 then .[0] else error("expected one auditor executable") end
' target/jankurai/auditor-build.jsonl)"
if [[ ! -f "$auditor" || -L "$auditor" || ! -x "$auditor" ]]; then
  echo 'Cargo auditor must be a regular executable, not a symlink' >&2
  exit 1
fi
sha256sum "$auditor" > target/jankurai/auditor.sha256
log "audit lane: exact-source full audit -> .jankurai/repo-score.{json,md}"
"$auditor" audit . \
  --full \
  --baseline agent/baselines/main.repo-score.json \
  --no-score-history \
  --fail-under 85 \
  --fail-on high \
  --json .jankurai/repo-score.json \
  --md .jankurai/repo-score.md
sha256sum --check target/jankurai/auditor.sha256
sha256sum agent/baselines/main.repo-score.json .jankurai/repo-score.json \
  .jankurai/repo-score.md > target/jankurai/auditor-reports.sha256

jq -e --slurpfile baseline agent/baselines/main.repo-score.json '
  .score >= ($baseline[0].score)
  and .raw_score >= ($baseline[0].raw_score)
  and ((.caps_applied | length) == 0)
  and (.decision.hard_findings == 0)
  and (.decision.passed == true)
' .jankurai/repo-score.json >/dev/null

assert_artifact .jankurai/repo-score.json
assert_artifact .jankurai/repo-score.md
