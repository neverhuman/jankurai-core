#!/usr/bin/env bash
# Shared CI helper module sourced by every ops/ci/<lane>.sh script.
# Single source of truth for tool version pins and artifact assertions so
# local runs and GitHub Actions execute the exact same commands.
set -euo pipefail

# Resolve the repository root regardless of where a lane is invoked from.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT

# CI must fail instead of opening an interactive credential prompt.
export GIT_TERMINAL_PROMPT=0

# Pinned tool versions. Lanes read these so CI and local environments match.
export RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-1.97.1}"
export GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.21.2}"
export CARGO_AUDIT_VERSION="${CARGO_AUDIT_VERSION:-0.22.1}"
export CARGO_DENY_VERSION="${CARGO_DENY_VERSION:-0.19.8}"
export ZIZMOR_VERSION="${ZIZMOR_VERSION:-1.25.2}"
export ACTIONLINT_VERSION="${ACTIONLINT_VERSION:-1.7.8}"
export SYFT_VERSION="${SYFT_VERSION:-1.40.0}"
export GRYPE_VERSION="${GRYPE_VERSION:-0.99.0}"
export NEXTEST_VERSION="${NEXTEST_VERSION:-0.9.137}"

# log <message> -- emit a structured progress line.
log() {
  printf '[ci] %s\n' "$*"
}

# require_tool <binary> -- fail fast with an actionable message when a pinned
# tool is missing from PATH so local parity gaps surface before the lane runs.
require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '[ci] missing required tool: %s\n' "$tool" >&2
    return 1
  fi
}

# assert_artifact <path> -- confirm a lane produced the artifact it promised.
assert_artifact() {
  local artifact="$1"
  if [ ! -e "$REPO_ROOT/$artifact" ]; then
    printf '[ci] expected artifact missing: %s\n' "$artifact" >&2
    return 1
  fi
  log "artifact present: $artifact"
}
