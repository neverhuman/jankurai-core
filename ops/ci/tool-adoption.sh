#!/usr/bin/env bash
# Tool-adoption evidence lane.
#
# jankurai replaces a fleet of ad-hoc tools (manual scoring, gitleaks-only
# security, hand-rolled coverage/contract drift checks) with first-class
# subcommands. This lane runs each adopted command in CI and writes its
# evidence artifact under target/jankurai/ so the audit can prove the
# replacement actually executed. The matching artifacts are uploaded by the
# workflow's actions/upload-artifact step.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

mkdir -p target/jankurai target/jankurai/security target/jankurai/coverage \
         target/jankurai/proofbind target/jankurai/proofmark

# Every adopted command must exercise the exact binary built from this commit.
# Keep the executable path literal below: tool-adoption auditing verifies the
# command surface, and an array indirection would hide real executions from it.
cargo build --locked --offline -p jankurai
test -x target/debug/jankurai

# audit-ci / proof-routing / contract-drift / authz-matrix /
# agent-tool-supply / release-readiness / cost-budget share one full ratchet.
install -m 0644 agent/baselines/main.repo-score.json \
  target/jankurai/accepted-baseline.json

# proofbind: changed-surface proof obligation routing.
log "tool-adoption: proofbind verify"
target/debug/jankurai proofbind verify . --changed-from origin/main
# Adopted artifacts: target/jankurai/proofbind/surface-witness.json
# target/jankurai/proofbind/obligations.json

# proofmark-rust: in-diff mutation and coverage witness for Rust.
log "tool-adoption: proofmark rust"
target/debug/jankurai proofmark rust . --obligations target/jankurai/proofbind/obligations.json
# Adopted artifacts: target/jankurai/proofmark/proofmark-receipt.json
# target/jankurai/proofmark/proof-receipt.json

# copy-code: duplication triage replacing ad-hoc copy-code review.
log "tool-adoption: copy-code"
lock_before="$(sha256sum Cargo.lock | cut -d' ' -f1)"
CARGO_NET_OFFLINE=true cargo run -p jankurai -- copy-code . --json target/jankurai/copy-code.json --md target/jankurai/copy-code.md
lock_after="$(sha256sum Cargo.lock | cut -d' ' -f1)"
[[ "$lock_after" == "$lock_before" ]] || die "copy-code changed Cargo.lock"
# Adopted artifacts: target/jankurai/copy-code.json target/jankurai/copy-code.md

# security: secret + dependency + SBOM/provenance evidence in one lane.
log "tool-adoption: security run"
target/debug/jankurai security run . --out target/jankurai/security/evidence.json
# Adopted artifact: target/jankurai/security/evidence.json

# ci/git/release bad-behavior: language-level workflow safety tests.
log "tool-adoption: language bad-behavior tests"
cargo test -p jankurai --test language_bad_behavior --locked --offline 2>&1 \
  | tee target/jankurai/language-bad-behavior.log
# Adopted artifact: target/jankurai/language-bad-behavior.log

# vibe-coverage: tips-backed vibe coverage replacing manual review.
log "tool-adoption: vibe coverage"
target/debug/jankurai vibe coverage --source agent/vibe-coverage.toml --tips agent/vibe-source-inventory.toml --json target/jankurai/vibe-coverage.json --md target/jankurai/vibe-coverage.md
# Adopted artifacts: target/jankurai/vibe-coverage.json target/jankurai/vibe-coverage.md

# coverage-evidence: coverage audit replacing line-only coverage gates.
log "tool-adoption: coverage audit"
target/debug/jankurai coverage audit . --config agent/coverage-sources.toml --json target/jankurai/coverage/coverage-audit.json --md target/jankurai/coverage/coverage-audit.md
# Adopted artifacts: target/jankurai/coverage/coverage-audit.json
# target/jankurai/coverage/coverage-audit.md

# Run the ratchet last so it evaluates every same-attempt artifact.
log "tool-adoption: final ratchet audit"
target/debug/jankurai audit . --mode ratchet --baseline target/jankurai/accepted-baseline.json --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md \
  --full \
  --no-score-history \
  --fail-under 85 \
  --fail-on high
# Adopted artifacts: target/jankurai/repo-score.json
# target/jankurai/repo-score.md and target/jankurai/repair-queue.jsonl
