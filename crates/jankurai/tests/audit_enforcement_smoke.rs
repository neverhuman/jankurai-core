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
        .arg("--full")
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
    assert_eq!(read_report(repo.path())["decision"]["passed"], false);
    assert_eq!(read_report(repo.path())["conformance_decision"], "block");
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
    assert_eq!(value["decision"]["passed"], false);
    assert_eq!(value["conformance_decision"], "block");
    assert_eq!(value["observed_conformance_level"], "HL1");
}

#[test]
fn fail_on_policy_controls_hard_findings() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());

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
    assert!(critical_only.status.success());
    let weak = read_report(repo.path());
    assert_eq!(weak["decision"]["hard_findings"], 0);
    assert_eq!(weak["conformance_decision"], "block");
    assert_ne!(weak["observed_conformance_level"], "HL3");

    let medium_repo = tempdir().unwrap();
    fs::write(medium_repo.path().join("README.md"), "# fixture\n").unwrap();
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
        "pub fn hidden() {\n    let marker = \"legacy\";\n    let _ = marker;\n}\n",
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
        "pub fn hidden() {\n    let marker = \"legacy\";\n    let _ = marker;\n}\n",
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

fn read_report(repo: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(repo.join("target/jankurai/repo-score.json")).unwrap())
        .unwrap()
}

fn write_weak_policy(repo: &Path) {
    fs::write(repo.join("agent/audit-policy.toml"),
        "minimum_score = 0\nfail_on = [\"critical\"]\nadvisory_on = [\"high\", \"medium\", \"low\"]\n").unwrap();
}

#[test]
fn cli_policy_overrides_bind_fingerprint_and_refresh_conformance() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    write_weak_policy(repo.path());
    assert!(audit(repo.path(), &["--mode", "standard"]).status.success());
    let weak = read_report(repo.path());
    let strict_args = [
        "--mode",
        "standard",
        "--fail-under",
        "90",
        "--fail-on",
        "critical,high",
    ];
    assert!(!audit(repo.path(), &strict_args).status.success());
    let strict = read_report(repo.path());
    assert_eq!(strict["decision"]["minimum_score"], 90);
    assert_eq!(strict["decision"]["passed"], false);
    assert!(strict["decision"]["hard_findings"].as_u64().unwrap() > 0);
    assert_eq!(strict["conformance_decision"], "block");
    assert_ne!(strict["observed_conformance_level"], "HL3");
    assert!(!strict["policy"]["advisory_on"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("high")));
    assert_ne!(strict["policy_fingerprint"], weak["policy_fingerprint"]);
    assert!(!audit(
        repo.path(),
        &[
            "--mode",
            "standard",
            "--fail-under",
            "90",
            "--fail-on",
            "high,critical,high"
        ]
    )
    .status
    .success());
    assert_eq!(
        read_report(repo.path())["policy_fingerprint"],
        strict["policy_fingerprint"]
    );
    assert!(audit(
        repo.path(),
        &[
            "--mode",
            "advisory",
            "--fail-under",
            "90",
            "--fail-on",
            "critical,high"
        ]
    )
    .status
    .success());
    let advisory = read_report(repo.path());
    assert_eq!(advisory["policy_fingerprint"], strict["policy_fingerprint"]);
    assert_eq!(advisory["decision"]["passed"], false);
    assert_eq!(advisory["conformance_decision"], "block");
    assert_ne!(advisory["report_fingerprint"], strict["report_fingerprint"]);
}

#[test]
fn explicit_policy_accepts_only_the_repository_policy_source() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    write_weak_policy(repo.path());
    let policy = repo.path().join("agent/audit-policy.toml");
    let mut fingerprint = None;
    for selected in [
        "agent/audit-policy.toml",
        "./agent/audit-policy.toml",
        policy.to_str().unwrap(),
    ] {
        let output = audit(repo.path(), &["--policy", selected]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let current = read_report(repo.path())["policy_fingerprint"].clone();
        if let Some(prior) = &fingerprint {
            assert_eq!(&current, prior);
        }
        fingerprint = Some(current);
    }
    let distinct = repo.path().join("different-policy.toml");
    fs::copy(&policy, &distinct).unwrap();
    for selected in [distinct.to_str().unwrap(), "missing.toml", "agent"] {
        let output = audit(repo.path(), &["--policy", selected]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported audit policy source"));
    }
    fs::remove_file(&policy).unwrap();
    assert!(!audit(repo.path(), &["--policy", policy.to_str().unwrap()])
        .status
        .success());
    assert!(audit(repo.path(), &["--mode", "advisory"]).status.success());
    fs::create_dir(&policy).unwrap();
    assert!(!audit(repo.path(), &["--mode", "advisory"]).status.success());
}

#[test]
fn cli_rejects_unknown_severity_and_out_of_range_floor() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    for args in [
        vec!["--fail-on", "severe"],
        vec!["--fail-under=-1"],
        vec!["--fail-under", "101"],
    ] {
        let output = audit(repo.path(), &args);
        assert!(!output.status.success(), "accepted {args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid audit policy"));
    }
    for floor in ["0", "100"] {
        assert!(
            audit(repo.path(), &["--mode", "advisory", "--fail-under", floor])
                .status
                .success()
        );
    }
}

#[test]
fn report_producer_version_and_schema_ignore_repository_claims() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    let version = Command::new(binary_path())
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        concat!("jankurai ", env!("CARGO_PKG_VERSION"))
    );
    for claimed in ["1.6.0", "999.99.99"] {
        fs::write(repo.path().join("agent/standard-version.toml"), format!("standard_version = \"0.9.0\"\nauditor_version = \"{claimed}\"\nschema_version = \"999.0.0\"\n")).unwrap();
        assert!(audit(repo.path(), &["--mode", "advisory"]).status.success());
        let report = read_report(repo.path());
        assert_eq!(report["auditor_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            report["policy"]["auditor_version"],
            report["auditor_version"]
        );
        assert_eq!(report["schema_version"], jankurai::model::SCHEMA_VERSION);
        assert_eq!(report["policy"]["schema_version"], report["schema_version"]);
    }
}

#[test]
fn changed_fast_failure_enforces_selected_mode_without_claiming_full_conformance() {
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    for mode in ["standard", "advisory"] {
        let output = audit(
            repo.path(),
            &[
                "--changed-fast",
                "--changed",
                "README.md",
                "--mode",
                mode,
                "--fail-under",
                "100",
            ],
        );
        assert_eq!(output.status.success(), mode == "advisory");
        let report = read_report(repo.path());
        assert_eq!(report["scope"]["mode"], "changed-fast");
        assert_eq!(report["decision"]["passed"], false);
        assert_eq!(report["observed_conformance_level"], "HL1");
        assert_ne!(report["conformance_decision"], "pass");
    }
}

#[test]
fn final_outcome_retains_ratchet_failure_and_new_proof_blocker() {
    use jankurai::audit::outcome::{enforce, finalize};
    let repo = tempdir().unwrap();
    write_base_repo(repo.path());
    let mut report = jankurai::audit::run_audit(repo.path(), &[]).unwrap();
    let mut proof = report.findings[0].clone();
    proof.severity = "high".into();
    report.findings.clear();
    report.caps_applied.clear();
    report.score = 84;
    finalize(&mut report, None).unwrap();
    assert!(!report.decision.as_ref().unwrap().passed);
    assert_eq!(report.conformance_decision, "review");
    assert!(enforce(&report).is_err());
    report.score = 85;
    finalize(&mut report, None).unwrap();
    assert!(report.decision.as_ref().unwrap().passed);
    assert_eq!(report.conformance_decision, "pass");
    enforce(&report).unwrap();
    let baseline = repo.path().join("baseline.json");
    let mut value = serde_json::to_value(&report).unwrap();
    value["score"] = serde_json::json!(86);
    fs::write(&baseline, serde_json::to_vec(&value).unwrap()).unwrap();
    report.policy.as_mut().unwrap().mode = Some("ratchet".into());
    finalize(&mut report, baseline.to_str()).unwrap();
    let decision = report.decision.as_ref().unwrap();
    assert!(!decision.passed);
    assert_eq!(decision.ratchet.as_ref().unwrap().score_delta, -1);
    assert!(!decision.ratchet.as_ref().unwrap().policy_changed);
    assert_eq!(report.conformance_decision, "review");
    assert!(enforce(&report).is_err());
    report.policy.as_mut().unwrap().mode = Some("release".into());
    report.findings.push(proof);
    finalize(&mut report, None).unwrap();
    assert_eq!(report.decision.as_ref().unwrap().hard_findings, 1);
    assert_eq!(report.conformance_decision, "block");
    assert_eq!(report.conformance_blockers.len(), 1);
    assert!(enforce(&report).is_err());
}
