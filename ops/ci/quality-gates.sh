#!/usr/bin/env bash
# Aggregate quality gate run by the pre-push hook and the local runner.
# Executes the same lanes CI runs so a green local gate means a green CI run.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "quality gates: required -> security evidence -> tool adoption -> final audit"
bash ops/ci/required.sh
bash ops/ci/security.sh
bash ops/ci/tool-adoption.sh
bash ops/ci/audit.sh
