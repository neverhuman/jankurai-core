use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn split_core_uses_local_reproducible_ci_entrypoints() {
    let root = repo_root();
    assert!(!root.join(".gitlab-ci.yml").exists());
    let local = fs::read_to_string(root.join("scripts/ci-local.sh")).unwrap();
    assert!(local.contains("ops/ci/required.sh"));
    assert!(local.contains("ops/ci/security.sh"));
    assert!(local.contains("ops/ci/quality-gates.sh"));

    let audit = fs::read_to_string(root.join("ops/ci/audit.sh")).unwrap();
    assert!(audit.contains("cargo run --locked --offline -p jankurai -- audit ."));
    assert!(audit.contains("--full"));
    assert!(audit.contains("agent/baselines/main.repo-score.json"));
    assert!(audit.contains(".caps_applied | length"));
    assert!(!audit.contains("/home/ubuntu/jankurai-split/jankurai"));

    let adoption = fs::read_to_string(root.join("ops/ci/tool-adoption.sh")).unwrap();
    assert!(adoption.contains("cargo build --locked --offline -p jankurai"));
    assert!(adoption.contains("test -x target/debug/jankurai"));
    assert!(adoption.contains("target/debug/jankurai proofbind verify"));
    assert!(adoption.contains("CARGO_NET_OFFLINE=true cargo run -p jankurai -- copy-code"));
    assert!(
        adoption.contains("security run . --strict --profile ci --script tools/security-lane.sh")
    );
    assert!(adoption.contains("copy-code changed Cargo.lock"));
    assert!(!adoption.contains("\"${JANKURAI[@]}\""));
    assert!(adoption.contains("target/jankurai/accepted-baseline.json"));
    assert!(adoption.contains("--full"));

    let required = fs::read_to_string(root.join("ops/ci/required.sh")).unwrap();
    assert!(required.contains("cargo clippy -p jankurai --all-targets --locked --offline"));

    let security = fs::read_to_string(root.join("tools/security-lane.sh")).unwrap();
    assert!(security.contains("cargo deny check --disable-fetch advisories bans sources"));
}
