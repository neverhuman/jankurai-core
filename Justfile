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
    cargo check --workspace --locked
    cargo nextest run --workspace

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
    gitleaks detect --source . --no-banner --redact
    cargo audit

# Jankurai self-audit lane: writes the repo-score artifacts that CI uploads.
audit:
    /home/ubuntu/jankurai-split/jankurai/.fusion/target/debug/jankurai audit . --no-score-history --json .jankurai/repo-score.json --md .jankurai/repo-score.md

# Print the declared version.
versions:
    cat VERSION
