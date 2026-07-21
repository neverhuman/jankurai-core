# jankurai-core root command surface.
# One-command setup and validation lanes for agents and CI.
# Every lane below is deterministic, hermetic, and runnable from the repo root.

# Default: list available lanes.
default:
    @just --list

# One-command bootstrap: install the toolchain components this repo needs.
setup:
    rustup component add rustfmt clippy
    cargo fetch --locked

# Alias for setup so `just install` and `just bootstrap` also resolve.
install: setup

bootstrap: setup

# Deterministic fast lane: the narrowest proof loop for agent iteration.
fast:
    GIT_TERMINAL_PROMPT=0 cargo check -p jankurai --locked --offline
    GIT_TERMINAL_PROMPT=0 cargo nextest run -p jankurai --locked --offline
    GIT_TERMINAL_PROMPT=0 cargo run -p jankurai --locked --offline -- audit . --mode advisory --full --no-score-history --fail-under 85 --fail-on high --json target/jankurai/audit-fast.json --md target/jankurai/audit-fast.md
    jq -e '(.score >= 85) and ((.caps_applied | length) == 0) and (.decision.hard_findings == 0) and (.decision.passed == true)' target/jankurai/audit-fast.json >/dev/null
    jq '{score, raw_score, caps_applied, findings, decision}' target/jankurai/audit-fast.json > target/jankurai/fast-score.json

# Optional narrow diagnostic. Its partial report is never used as release
# evidence; `fast` above always finishes with the fail-closed full audit.
audit-changed path:
    GIT_TERMINAL_PROMPT=0 cargo run -p jankurai --locked --offline -- audit . --changed-fast --changed "{{path}}" --no-score-history --json target/jankurai/audit-changed.json --md target/jankurai/audit-changed.md

# Run the full local check: format, lint, fast lane, security, and audit.
check: fmt lint fast security audit

# Verify is an alias of check for agents that look for a `verify` lane.
verify: check

fmt:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# Run the workspace test suite.
test:
    GIT_TERMINAL_PROMPT=0 cargo nextest run --workspace --locked --offline

# Security lane: secret scanning plus dependency vulnerability scanning.
# gitleaks scans for committed secrets; cargo audit checks the Rust dependency tree.
security:
    bash ops/ci/security.sh

# Exact-source full self-audit lane: writes the repo-score artifacts CI uploads.
audit:
    bash ops/ci/audit.sh

# Print the declared version.
versions:
    cat VERSION
