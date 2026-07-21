use std::fs;
use std::path::{Path, PathBuf};

use jankurai::commands::conformance::{build_report, render_tex_table, ConformanceRunArgs};
use jankurai::validation::{self, ArtifactSchema};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn conformance_runner_handles_an_empty_member_owned_fixture_set() {
    let schema_root = workspace_root();
    let scratch = tempfile::tempdir().unwrap();
    fs::create_dir_all(scratch.path().join("fixtures")).unwrap();
    fs::create_dir_all(scratch.path().join("expected")).unwrap();
    let args = ConformanceRunArgs {
        workspace: scratch.path().to_path_buf(),
        fixtures: PathBuf::from("fixtures"),
        expected: PathBuf::from("expected"),
        out: "target/jankurai/conformance-results.json".into(),
        md: "target/jankurai/conformance-results.md".into(),
        tex: "target/jankurai/conformance-results.tex".into(),
    };

    let report = build_report(&args).expect("build empty conformance report");
    validation::validate_serializable(&schema_root, ArtifactSchema::ConformanceResults, &report)
        .expect("conformance report validates");
    assert_eq!(report.fixture_count, 0);
    assert_eq!(report.pass_count, 0);
    assert_eq!(report.fail_count, 0);
    assert!(report.results.is_empty());

    let tex = render_tex_table(&report, &args);
    assert!(tex.contains("\\label{tab:conformance-results}"));
}
