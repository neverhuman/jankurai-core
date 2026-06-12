#!/usr/bin/env bash
# Security lane: secret scanning plus dependency vulnerability scanning.
# gitleaks scans for committed secrets; cargo audit checks the Rust dependency
# tree. The same lane runs locally via `just security`.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "security lane: gitleaks + cargo audit"
gitleaks detect --source . --no-banner --redact
cargo audit
