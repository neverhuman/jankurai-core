use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

use jankurai::audit::fs::{inventory_repo_detailed, InventoryOptions};

fn binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_jankurai")
}

fn write_base_repo(repo: &Path) {
    fs::write(
        repo.join("AGENTS.md"),
        "Read agent/JANKURAI_STANDARD.md first.\n",
    )
    .unwrap();
    fs::write(repo.join("README.md"), "# fixture\n").unwrap();
    fs::create_dir_all(repo.join("agent")).unwrap();
    fs::write(
        repo.join("agent/JANKURAI_STANDARD.md"),
        "Standard version: `0.9.0`\n",
    )
    .unwrap();
    fs::create_dir_all(repo.join("docs")).unwrap();
    fs::write(
        repo.join("docs/agent-native-standard.md"),
        "Standard version: `0.9.0`\n",
    )
    .unwrap();
}

fn audit(repo: &Path, extra: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(binary_path());
    cmd.arg("audit")
        .arg(repo)
        .arg("--json")
        .arg(repo.join("target/jankurai/repo-score.json"))
        .arg("--md")
        .arg(repo.join("target/jankurai/repo-score.md"))
        .arg("--no-score-history");
    for arg in extra {
        cmd.arg(arg);
    }
    cmd.output().unwrap()
}

#[test]
fn standard_mode_fails_closed_but_writes_artifacts() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());

    let output = audit(repo.path(), &["--mode", "standard", "--fail-under", "0"]);

    assert!(!output.status.success());
    assert!(repo
        .path()
        .join("target/jankurai/repo-score.json")
        .is_file());
    assert!(repo.path().join("target/jankurai/repo-score.md").is_file());
}

#[test]
fn advisory_mode_keeps_failed_decision_nonblocking() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());

    let output = audit(repo.path(), &["--mode", "advisory", "--fail-under", "0"]);

    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(repo.path().join("target/jankurai/repo-score.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(value["decision"]["status"], "advisory");
}

#[test]
fn omitted_fail_on_defaults_to_critical_and_high() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    fs::write(
        repo.path().join("agent/audit-policy.toml"),
        "minimum_score = 0\n",
    )
    .unwrap();

    let report = jankurai::audit::run_audit(repo.path(), &[]).unwrap();
    assert_eq!(
        report.policy.as_ref().unwrap().fail_on,
        vec!["critical".to_string(), "high".to_string()]
    );
}

#[test]
fn explicit_empty_fail_on_stays_empty() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    fs::write(
        repo.path().join("agent/audit-policy.toml"),
        "minimum_score = 0\nfail_on = []\nadvisory_on = []\n",
    )
    .unwrap();

    let report = jankurai::audit::run_audit(repo.path(), &[]).unwrap();
    assert!(report.policy.as_ref().unwrap().fail_on.is_empty());
}

#[test]
fn fail_on_policy_counts_do_not_erase_conformance_blockers() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    fs::write(
        repo.path().join("agent/audit-policy.toml"),
        "minimum_score = 0\nfail_on = [\"critical\"]\n",
    )
    .unwrap();

    let critical_only = audit(
        repo.path(),
        &[
            "--mode",
            "standard",
            "--fail-under",
            "0",
            "--fail-on",
            "critical",
        ],
    );
    assert!(!critical_only.status.success());
    let report: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(repo.path().join("target/jankurai/repo-score.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["decision"]["hard_findings"], 0);
    assert_eq!(report["decision"]["passed"], false);
    assert_eq!(report["conformance_decision"], "block");
    assert!(!report["conformance_blockers"]
        .as_array()
        .unwrap()
        .is_empty());

    let medium_repo = tempdir().unwrap();
    write_base_repo(medium_repo.path());
    fs::write(
        medium_repo.path().join("agent/audit-policy.toml"),
        "minimum_score = 0\nfail_on = [\"medium\"]\n",
    )
    .unwrap();
    let medium = audit(
        medium_repo.path(),
        &[
            "--mode",
            "standard",
            "--fail-under",
            "0",
            "--fail-on",
            "medium",
        ],
    );
    assert!(!medium.status.success());
    let report =
        fs::read_to_string(medium_repo.path().join("target/jankurai/repo-score.json")).unwrap();
    assert!(
        report.contains("\"hard_findings\"") && !report.contains("\"hard_findings\": 0"),
        "{report}"
    );
    assert!(
        report.contains("\"passed\": false") || report.contains("\"status\": \"fail\""),
        "{report}"
    );
}

#[test]
fn invalid_policy_severity_fails_loading() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    fs::write(
        repo.path().join("agent/audit-policy.toml"),
        "minimum_score = 0\nfail_on = [\"severe\"]\nadvisory_on = []\n",
    )
    .unwrap();

    let output = audit(repo.path(), &["--mode", "standard"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid audit policy severity"));
}

#[test]
fn direct_file_exclusion_does_not_hide_tracked_rust() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    fs::create_dir_all(repo.path().join("crates/foo/src")).unwrap();
    fs::write(
        repo.path().join("crates/foo/src/lib.rs"),
        "pub fn hidden() {\n    /* TODO: remove legacy compatibility fallback after migration. */\n}\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/audit-policy.toml"),
        r#"
minimum_score = 0
[scan]
excluded_paths = ["crates/foo/src/lib.rs"]
"#,
    )
    .unwrap();

    let report = jankurai::audit::run_audit(repo.path(), &[]).unwrap();
    assert!(report.findings.iter().any(|finding| {
        finding.path == "crates/foo/src/lib.rs"
            && finding.rule_id.as_deref() == Some("HLT-001-DEAD-MARKER")
    }));
}

#[test]
fn broad_root_exclusion_does_not_hide_tracked_rust() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    fs::create_dir_all(repo.path().join("crates/foo/src")).unwrap();
    fs::write(
        repo.path().join("crates/foo/src/lib.rs"),
        "pub fn hidden() {\n    /* TODO: remove legacy compatibility fallback after migration. */\n}\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/audit-policy.toml"),
        r#"
minimum_score = 0
[scan]
extra_excluded_globs = ["crates/**"]
"#,
    )
    .unwrap();

    let report = jankurai::audit::run_audit(repo.path(), &[]).unwrap();
    assert!(report.findings.iter().any(|finding| {
        finding.path == "crates/foo/src/lib.rs"
            && finding.rule_id.as_deref() == Some("HLT-001-DEAD-MARKER")
    }));
}

#[test]
fn control_plane_exclusions_do_not_hide_agents_or_workflows() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    fs::create_dir_all(repo.path().join(".github/workflows")).unwrap();
    fs::write(
        repo.path().join(".github/workflows/ci.yml"),
        "name: ci\njobs:\n  audit:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@master\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/audit-policy.toml"),
        r#"
minimum_score = 0
[scan]
excluded_paths = ["AGENTS.md", ".github/"]
"#,
    )
    .unwrap();

    let report = jankurai::audit::run_audit(repo.path(), &[]).unwrap();
    let inventory =
        inventory_repo_detailed(repo.path(), &InventoryOptions::from_policy(repo.path())).unwrap();
    assert!(!report
        .caps_applied
        .iter()
        .any(|cap| cap == "no-root-agent-instructions"));
    assert!(inventory
        .files
        .iter()
        .any(|file| file.rel_path == ".github/workflows/ci.yml"));
}

#[test]
fn isolated_empty_repo_report_includes_ratchet_score_delta() {
    let repo = tempdir().unwrap();
    let home = tempdir().unwrap();
    let config = tempdir().unwrap();
    let cache = tempdir().unwrap();

    let output = Command::new(binary_path())
        .arg("audit")
        .arg(repo.path())
        .arg("--mode")
        .arg("advisory")
        .arg("--json")
        .arg(repo.path().join("repo-score.json"))
        .arg("--md")
        .arg(repo.path().join("repo-score.md"))
        .arg("--no-score-history")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", config.path())
        .env("XDG_CACHE_HOME", cache.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo.path().join("repo-score.json")).unwrap())
            .unwrap();
    assert_eq!(value["decision"]["ratchet"]["score_delta"], 0);
}

#[test]
fn advisory_audit_does_not_rewrite_committed_badges() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    fs::write(
        repo.path().join("agent/badge.toml"),
        "enabled = true\n\
         score = \".jankurai/repo-score.json\"\n\
         svg = \"agent/jankurai-badge.svg\"\n\
         json = \"agent/jankurai-badge.json\"\n\
         readme = \"README.md\"\n\
         link = \"agent/jankurai-badge.json\"\n\
         update_readme = true\n\
         label = \"jankurai\"\n",
    )
    .unwrap();
    let readme =
        "# fixture\n<!-- jankurai-badge:start -->\ncommitted badge\n<!-- jankurai-badge:end -->\n";
    fs::write(repo.path().join("README.md"), readme).unwrap();
    fs::write(
        repo.path().join("agent/jankurai-badge.svg"),
        "SENTINEL_SVG\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/jankurai-badge.json"),
        "SENTINEL_JSON\n",
    )
    .unwrap();

    let output = audit(repo.path(), &["--mode", "advisory", "--fail-under", "0"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(repo.path().join("README.md")).unwrap(),
        readme
    );
    assert_eq!(
        fs::read_to_string(repo.path().join("agent/jankurai-badge.svg")).unwrap(),
        "SENTINEL_SVG\n"
    );
    assert_eq!(
        fs::read_to_string(repo.path().join("agent/jankurai-badge.json")).unwrap(),
        "SENTINEL_JSON\n"
    );
}
