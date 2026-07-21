#!/usr/bin/env bash
# Security lane: secret scanning plus dependency vulnerability scanning.
# gitleaks scans for committed secrets; cargo audit checks the Rust dependency
# tree. The same lane runs locally via `just security`.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "security lane: local secret, dependency, policy, workflow, SBOM, and vulnerability proof"
bash tools/security-lane.sh ci

assert_artifact target/jankurai/security/sbom.json
assert_artifact target/jankurai/security/provenance-inputs.sha256
