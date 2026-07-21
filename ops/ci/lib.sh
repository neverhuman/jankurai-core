#!/usr/bin/env bash
# Shared CI helper module sourced by every ops/ci/<lane>.sh script.
# Single source of truth for tool version pins and artifact assertions so
# local runs and GitHub Actions execute the exact same commands.
set -euo pipefail

# Resolve the repository root regardless of where a lane is invoked from.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT

# Pinned tool versions. Lanes read these so CI and local environments match.
export RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-stable}"
export GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.18.4}"
export CARGO_AUDIT_VERSION="${CARGO_AUDIT_VERSION:-0.21.0}"
export NEXTEST_VERSION="${NEXTEST_VERSION:-0.9}"

# Production-authoritative Jankurai identity. This is intentionally not
# overrideable: local/Jeryu semantic lanes must never select an ambient PATH,
# Cargo, fusion, or self-installed binary.
readonly GOVERNED_JANKURAI_BIN="/home/ubuntu/.jeryu/bin/jankurai"
readonly GOVERNED_JANKURAI_VERSION="jankurai 1.6.11"
readonly GOVERNED_JANKURAI_SHA256="fdb42e5fa7d9851c0729e59bf1e582c895aa9cfc03a7175b420c6025d2fd014e"
readonly GOVERNED_JANKURAI_RECEIPT="/home/ubuntu/.jeryu/receipts/jankurai/sha256/494ea02af28e6aa7fb2f817831dc8f00df102398677779f7decfce55b3b20b98.json"
readonly GOVERNED_JANKURAI_RECEIPT_SHA256="494ea02af28e6aa7fb2f817831dc8f00df102398677779f7decfce55b3b20b98"

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

# require_governed_jankurai -- fail closed unless both the immutable binary and
# its production installation receipt have the exact reviewed identities.
require_governed_jankurai() {
  local actual_path actual_receipt_path actual_sha actual_version receipt_sha

  require_tool jq
  require_tool realpath
  require_tool sha256sum

  if [[ ! -f "$GOVERNED_JANKURAI_BIN" || -L "$GOVERNED_JANKURAI_BIN" ||
        ! -x "$GOVERNED_JANKURAI_BIN" ]]; then
    printf '[ci] governed jankurai is not an executable regular non-symlink: %s\n' \
      "$GOVERNED_JANKURAI_BIN" >&2
    return 1
  fi
  actual_path="$(realpath -e -- "$GOVERNED_JANKURAI_BIN")"
  if [[ "$actual_path" != "$GOVERNED_JANKURAI_BIN" ]]; then
    printf '[ci] governed jankurai path is not canonical: %s -> %s\n' \
      "$GOVERNED_JANKURAI_BIN" "$actual_path" >&2
    return 1
  fi

  actual_version="$("$GOVERNED_JANKURAI_BIN" --version 2>/dev/null || true)"
  actual_sha="$(sha256sum "$GOVERNED_JANKURAI_BIN" | awk '{print $1}')"
  if [[ "$actual_version" != "$GOVERNED_JANKURAI_VERSION" ||
        "$actual_sha" != "$GOVERNED_JANKURAI_SHA256" ]]; then
    printf '[ci] governed jankurai identity mismatch: version=%s sha256=%s\n' \
      "${actual_version:-missing}" "${actual_sha:-missing}" >&2
    return 1
  fi

  if [[ ! -f "$GOVERNED_JANKURAI_RECEIPT" || -L "$GOVERNED_JANKURAI_RECEIPT" ]]; then
    printf '[ci] governed jankurai production receipt is not a regular non-symlink: %s\n' \
      "$GOVERNED_JANKURAI_RECEIPT" >&2
    return 1
  fi
  actual_receipt_path="$(realpath -e -- "$GOVERNED_JANKURAI_RECEIPT")"
  receipt_sha="$(sha256sum "$GOVERNED_JANKURAI_RECEIPT" | awk '{print $1}')"
  if [[ "$actual_receipt_path" != "$GOVERNED_JANKURAI_RECEIPT" ||
        "$receipt_sha" != "$GOVERNED_JANKURAI_RECEIPT_SHA256" ]]; then
    printf '[ci] governed jankurai production receipt identity mismatch: path=%s sha256=%s\n' \
      "$actual_receipt_path" "${receipt_sha:-missing}" >&2
    return 1
  fi
  if ! jq -e \
    --arg binary "$GOVERNED_JANKURAI_SHA256" \
    --arg version "$GOVERNED_JANKURAI_VERSION" \
    --arg path "$GOVERNED_JANKURAI_BIN" \
    '.schema == "jeryu.jankurai-installation/v1" and
     .binary.sha256 == $binary and .binary.version_output == $version and
     .installation.path == $path and .installation.atomic == true and
     .governance.status == "governed" and .governance.protected_main == true and
     .governance.protection_policy == "immutable-main-v1" and
     .test_mode == false and .conclusion == "success"' \
    "$GOVERNED_JANKURAI_RECEIPT" >/dev/null; then
    printf '[ci] governed jankurai production receipt semantics mismatch: %s\n' \
      "$GOVERNED_JANKURAI_RECEIPT" >&2
    return 1
  fi
}

# run_governed_jankurai <args...> -- the only operational semantic-auditor
# entrypoint in this repository.
run_governed_jankurai() {
  require_governed_jankurai
  JANKURAI_NO_UPDATE_CHECK=1 GIT_TERMINAL_PROMPT=0 \
    "$GOVERNED_JANKURAI_BIN" "$@"
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
