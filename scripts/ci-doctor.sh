#!/usr/bin/env bash
# CI doctor: confirms the local environment has every tool the ops/ci lanes
# depend on, with the versions pinned in ops/ci/lib.sh. Run this before pushing
# to verify your machine matches what GitHub Actions provides.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../ops/ci/lib.sh"

log "ci-doctor: checking required tools"

status=0
for tool in cargo rustc cargo-nextest gitleaks cargo-audit cargo-deny zizmor actionlint syft grype; do
  if command -v "$tool" >/dev/null 2>&1; then
    log "ok: $tool ($(command -v "$tool"))"
  else
    printf '[ci] MISSING: %s\n' "$tool" >&2
    status=1
  fi
done

check_version() {
  local tool="$1"
  local expected="$2"
  shift 2
  local actual
  actual="$("$@" 2>&1)"
  if [[ "$actual" != *"$expected"* ]]; then
    printf '[ci] VERSION MISMATCH: %s expected %s, got %s\n' "$tool" "$expected" "$actual" >&2
    status=1
  fi
}

check_version cargo-nextest "$NEXTEST_VERSION" cargo-nextest --version
check_version gitleaks "$GITLEAKS_VERSION" gitleaks version
check_version cargo-audit "$CARGO_AUDIT_VERSION" cargo audit --version
check_version cargo-deny "$CARGO_DENY_VERSION" cargo deny --version
check_version zizmor "$ZIZMOR_VERSION" zizmor --version
check_version actionlint "$ACTIONLINT_VERSION" actionlint -version
check_version syft "$SYFT_VERSION" syft version
check_version grype "$GRYPE_VERSION" grype version

log "pinned versions verified for nextest and all seven security tools"

if [ "$status" -ne 0 ]; then
  printf '[ci] environment does not match CI; install the tools above\n' >&2
fi
exit "$status"
