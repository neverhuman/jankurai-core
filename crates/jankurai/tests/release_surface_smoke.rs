use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn split_core_release_surface_is_binary_source_only() {
    let root = repo_root();
    for hub_or_deploy_surface in [
        "action.yml",
        "jankurai-installer.sh",
        "ops/ci/release-publish.sh",
        "ops/homebrew/jankurai.rb",
    ] {
        assert!(
            !root.join(hub_or_deploy_surface).exists(),
            "split core must not duplicate {hub_or_deploy_surface}"
        );
    }
    let release = fs::read_to_string(root.join("docs/release.md")).unwrap();
    assert!(release.contains("jankurai-core"));
    assert!(release.contains("just check"));
}
