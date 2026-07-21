#!/usr/bin/env bash
# Public-mirror CI bootstrap only. Authoritative local Jeryu proof lanes never
# call this script; their tools are installed from the sealed host tool cache.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

cargo install --locked cargo-audit --version "$CARGO_AUDIT_VERSION"
cargo install --locked cargo-deny --version "$CARGO_DENY_VERSION"
cargo install --locked zizmor --version "$ZIZMOR_VERSION"

install_bin="${CARGO_HOME:-$HOME/.cargo}/bin"
mkdir -p "$install_bin"
GOBIN="$install_bin" go install "github.com/gitleaks/gitleaks/v8@v$GITLEAKS_VERSION"
GOBIN="$install_bin" go install "github.com/rhysd/actionlint/cmd/actionlint@v$ACTIONLINT_VERSION"
GOBIN="$install_bin" go install "github.com/anchore/syft/cmd/syft@v$SYFT_VERSION"
GOBIN="$install_bin" go install "github.com/anchore/grype/cmd/grype@v$GRYPE_VERSION"

bash scripts/ci-doctor.sh
