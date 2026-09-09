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
archive_root="$(mktemp -d)"
trap 'rm -rf "$archive_root"' EXIT

# Install a pinned GitHub-release binary after verifying its published checksum.
# go install is not used: module paths for these tools have moved, and release
# tarballs are the same artifacts sibling repos already pin.
install_release() {
  local repository="$1" version="$2" binary="$3" archive="$4"
  local checksums="${binary}_${version}_checksums.txt"
  local base="https://github.com/$repository/releases/download/v$version"
  curl --proto '=https' --tlsv1.2 -fsSL "$base/$archive" -o "$archive_root/$archive"
  curl --proto '=https' --tlsv1.2 -fsSL "$base/$checksums" -o "$archive_root/$checksums"
  (cd "$archive_root" && awk -v name="$archive" '$2 == name { print; count++ } END { if (count != 1) exit 1 }' "$checksums" > selected.sha256 && sha256sum -c selected.sha256)
  tar -xzf "$archive_root/$archive" -C "$archive_root" "$binary"
  install -m 0755 "$archive_root/$binary" "$install_bin/$binary"
  "$install_bin/$binary" --version || "$install_bin/$binary" version
}

install_release gitleaks/gitleaks "$GITLEAKS_VERSION" gitleaks "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
install_release rhysd/actionlint "$ACTIONLINT_VERSION" actionlint "actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"
install_release anchore/syft "$SYFT_VERSION" syft "syft_${SYFT_VERSION}_linux_amd64.tar.gz"
install_release anchore/grype "$GRYPE_VERSION" grype "grype_${GRYPE_VERSION}_linux_amd64.tar.gz"

# Populate the locked crate and git dependency cache before offline quality gates.
cargo fetch --locked

bash scripts/ci-doctor.sh
