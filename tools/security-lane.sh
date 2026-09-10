#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

profile="${1:-ci}"
mkdir -p target/jankurai/security
run_dir="$(mktemp -d target/jankurai/security/run.XXXXXX)"
has_package=false
lane_exit=0

run_step() {
    local label="$1"
    local tool="$2"
    local shell_command="$3"
    local advisory="$4"
    shift 4

    set +e
    "$@"
    local exit_code=$?
    set -e
    local status="ran"
    if [[ ${exit_code} -ne 0 ]]; then
        status="failed"
        if [[ "${advisory}" == "false" && "${lane_exit}" -eq 0 ]]; then
            lane_exit="${exit_code}"
        fi
    fi
    printf 'jankurai-security-step={"label":"%s","tool":"%s","shell_command":"%s","status":"%s","advisory":%s,"exit_code":%d}\n' \
        "${label}" "${tool}" "${shell_command}" "${status}" "${advisory}" "${exit_code}"
    return 0
}

printf '[security] profile=%s secret scan\n' "${profile}"
run_step gitleaks gitleaks 'gitleaks detect --source . --no-banner --redact' false \
    gitleaks detect --source . --no-banner --redact

if [[ -f Cargo.toml ]]; then
    has_package=true
    printf '[security] Rust dependency and policy scans\n'
    run_step cargo-audit cargo-audit 'cargo audit' false \
        cargo audit
    run_step cargo-deny cargo-deny 'cargo deny --locked check advisories bans sources' false \
        cargo deny --locked check advisories bans sources
fi

if [[ -f package.json ]]; then
    has_package=true
    printf '[security] Node dependency scan\n'
    run_step npm-audit npm 'npm audit --audit-level=high' false \
        npm audit --audit-level=high
fi

if [[ -d .github/workflows ]]; then
    printf '[security] workflow hardening\n'
    run_step zizmor zizmor 'zizmor .github/workflows' false \
        zizmor .github/workflows
    run_step actionlint actionlint 'actionlint .github/workflows/*.yml' false \
        actionlint .github/workflows/*.yml
fi

if [[ "${has_package}" == false ]]; then
    printf '[security] no package manifest; dependency inventory not applicable\n'
    exit "${lane_exit}"
fi

printf '[security] SBOM and vulnerability scan\n'
run_step syft syft 'syft scan dir:. -o cyclonedx-json=target/jankurai/security/sbom.json' false \
    syft scan dir:. --exclude './target/**' --exclude './.git/**' --exclude './node_modules/**' \
        -o "cyclonedx-json=$run_dir/sbom.json"
if [[ -f "$run_dir/sbom.json" && -s "$run_dir/sbom.json" && ! -L "$run_dir/sbom.json" ]]; then
    run_step grype grype 'grype sbom:target/jankurai/security/sbom.json --fail-on high' false \
        grype "sbom:$run_dir/sbom.json" --fail-on high
else
    printf '[security] current scan produced no regular nonempty SBOM\n' >&2
    if [[ "$lane_exit" -eq 0 ]]; then lane_exit=1; fi
fi

# Retain every attempted scan. Stable paths are published only after all tools
# succeed; the Rust wrapper then validates the full offline CycloneDX schema.
if [[ "$lane_exit" -ne 0 ]]; then
    exit "$lane_exit"
fi
if [[ -L target/jankurai/security/sbom.json || (-e target/jankurai/security/sbom.json && ! -f target/jankurai/security/sbom.json) ]]; then
    printf '[security] refusing a non-regular SBOM destination\n' >&2
    exit 1
fi
cp "$run_dir/sbom.json" "$run_dir/publish-sbom.json"
mv -T "$run_dir/publish-sbom.json" target/jankurai/security/sbom.json

printf '[security] provenance input digest\n'
provenance_inputs=(target/jankurai/security/sbom.json)
if [[ -f Cargo.lock ]]; then
    provenance_inputs=(Cargo.lock "${provenance_inputs[@]}")
fi
if [[ -f package-lock.json ]]; then
    provenance_inputs=(package-lock.json "${provenance_inputs[@]}")
fi
sha256sum "${provenance_inputs[@]}" > target/jankurai/security/provenance-inputs.sha256
exit "${lane_exit}"
