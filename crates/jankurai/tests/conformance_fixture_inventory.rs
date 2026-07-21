use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn split_core_does_not_duplicate_the_conformance_fixture_repository() {
    let root = repo_root();
    assert!(!root.join("conformance/fixtures").exists());
    let split = fs::read_to_string(root.join("agent/split-member.toml")).unwrap();
    assert!(split.contains("repo = \"jankurai-core\""));
    assert!(!split.contains("repo = \"jankurai-conformance\""));
}
