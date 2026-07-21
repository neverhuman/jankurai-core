use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn split_core_does_not_duplicate_the_hub_action() {
    let root = repo_root();
    assert!(!root.join("action.yml").exists());
    let split = fs::read_to_string(root.join("agent/split-member.toml")).unwrap();
    assert!(split.contains("repo = \"jankurai-core\""));
    assert!(split.contains("role = \"Rust package and binary source for"));
}
