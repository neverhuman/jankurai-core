#!/usr/bin/env bash
# Local entry point for the CI lanes. Delegates to the exact same
# ops/ci/<lane>.sh scripts the GitHub Actions and GitLab workflows call, so
# local runs never drift from CI.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

lane="${1:-all}"
case "$lane" in
  required) bash ops/ci/required.sh ;;
  fast)     bash ops/ci/fast.sh ;;
  security) bash ops/ci/security.sh ;;
  audit)    bash ops/ci/audit.sh ;;
  gates|all) bash ops/ci/quality-gates.sh ;;
  quick)    bash ops/ci/quality-gates.sh ;;
  coverage) bash ops/ci/coverage-llvm.sh ;;
  release) RELEASE_TAG="${LOCAL_RELEASE_TAG:-}" bash ops/ci/release-audit-gate.sh ;;
  release-build)
    RELEASE_TAG="${LOCAL_RELEASE_TAG:-}" \
      TARGET="${LOCAL_RELEASE_TARGET:-}" \
      bash ops/ci/release-build.sh
    ;;
  release-publish)
    RELEASE_TAG="${LOCAL_RELEASE_TAG:-}" \
      GH_TOKEN="${GH_TOKEN:-}" \
      bash ops/ci/release-publish.sh
    ;;
  shadow) bash ops/ci/post-main-shadow.sh ;;
  container) bash ops/ci/run-in-container.sh "bash ops/ci/${2:-audit.sh}" ;;
  *) echo "usage: $0 {required|fast|security|audit|gates|quick|coverage|release|release-build|release-publish|shadow|container|all}" >&2; exit 2 ;;
esac
