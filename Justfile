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
    cargo check -p jankurai --locked
    cargo nextest run -p jankurai
    cargo run -p jankurai -- audit . --changed-fast --changed Cargo.lock --no-score-history --json target/jankurai/audit-fast.json --md target/jankurai/audit-fast.md
    jq '{score, raw_score, caps_applied, findings}' target/jankurai/audit-fast.json > target/jankurai/fast-score.json

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
    cargo nextest run --workspace

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
