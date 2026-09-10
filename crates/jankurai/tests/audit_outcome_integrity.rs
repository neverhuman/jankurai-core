use jankurai::audit::{
    outcome, policy::AuditMode, run_audit, run_audit_timed_with_policy, AuditOptions,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

fn fixture(policy: &str) -> TempDir {
    let repo = tempfile::tempdir().unwrap();
    fs::create_dir(repo.path().join("agent")).unwrap();
    fs::write(repo.path().join("agent/audit-policy.toml"), policy).unwrap();
    fs::write(
        repo.path().join("AGENTS.md"),
        "Read agent/JANKURAI_STANDARD.md.\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/JANKURAI_STANDARD.md"),
        "Standard version: `0.9.0`\n",
    )
    .unwrap();
    fs::write(repo.path().join("README.md"), "# Audit fixture\n").unwrap();
    repo
}

fn audit(repo: &Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_jankurai"))
        .args(["audit", "--full", "--no-score-history", "--no-badge"])
        .arg(repo)
        .arg("--json")
        .arg(repo.join("target/report.json"))
        .arg("--md")
        .arg(repo.join("target/report.md"))
        .args(extra)
        .output()
        .unwrap()
}

fn report(repo: &Path) -> Value {
    serde_json::from_slice(&fs::read(repo.join("target/report.json")).unwrap()).unwrap()
}

fn rejects_without_replacing_reports(repo: &Path, args: &[&str], diagnostic: &str) {
    fs::create_dir_all(repo.join("target")).unwrap();
    for name in ["report.json", "report.md"] {
        fs::write(repo.join("target").join(name), "prior evidence\n").unwrap();
    }
    let output = audit(repo, args);
    assert!(!output.status.success(), "unexpected success: {args:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(diagnostic),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for name in ["report.json", "report.md"] {
        assert_eq!(
            fs::read_to_string(repo.join("target").join(name)).unwrap(),
            "prior evidence\n"
        );
    }
}

#[test]
fn advisory_exit_does_not_turn_failure_into_a_pass() {
    let repo = fixture("minimum_score = 100\n");
    let output = audit(repo.path(), &["--mode", "advisory"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = report(repo.path());
    assert_eq!(value["decision"]["status"], "advisory");
    assert_eq!(value["decision"]["passed"], false);
    assert_eq!(value["observed_conformance_level"], "HL1");
    assert_eq!(value["conformance_decision"], "review");
    let output = audit(repo.path(), &["--mode", "standard"]);
    assert!(!output.status.success());
    let value = report(repo.path());
    assert_eq!(value["decision"]["passed"], false);
    assert_ne!(value["conformance_decision"], "pass");
}

#[test]
fn cli_cannot_weaken_policy_and_effective_overrides_change_fingerprint() {
    let repo = fixture("minimum_score = 90\nfail_on = [\"critical\", \"high\"]\n");
    assert!(audit(repo.path(), &["--mode", "advisory"]).status.success());
    let original = report(repo.path());
    assert!(audit(
        repo.path(),
        &[
            "--mode",
            "advisory",
            "--fail-under",
            "0",
            "--fail-on",
            "critical"
        ]
    )
    .status
    .success());
    let retained = report(repo.path());
    assert_eq!(retained["policy"]["minimum_score"], 90);
    assert_eq!(retained["policy"]["fail_on"], json!(["critical", "high"]));
    assert_eq!(
        retained["policy_fingerprint"],
        original["policy_fingerprint"]
    );
    assert!(audit(
        repo.path(),
        &[
            "--mode",
            "advisory",
            "--fail-under",
            "95",
            "--fail-on",
            "medium"
        ]
    )
    .status
    .success());
    let stronger = report(repo.path());
    assert_eq!(stronger["policy"]["minimum_score"], 95);
    assert_eq!(stronger["decision"]["minimum_score"], 95);
    assert_ne!(
        stronger["policy_fingerprint"],
        original["policy_fingerprint"]
    );
    rejects_without_replacing_reports(
        repo.path(),
        &["--mode", "advisory", "--fail-on", "imaginary"],
        "invalid audit policy severity",
    );
}

#[test]
fn explicit_policy_must_be_the_policy_consumed_by_every_scanner() {
    let repo = fixture("minimum_score = 100\n");
    fs::write(repo.path().join("alternate.toml"), "minimum_score = 0\n").unwrap();
    rejects_without_replacing_reports(
        repo.path(),
        &["--mode", "advisory", "--policy", "alternate.toml"],
        "unsupported audit policy source",
    );
    rejects_without_replacing_reports(
        repo.path(),
        &["--mode", "advisory", "--policy", "missing.toml"],
        "unsupported audit policy source",
    );
    for path in [
        "agent/audit-policy.toml".to_string(),
        repo.path()
            .join("agent/audit-policy.toml")
            .display()
            .to_string(),
    ] {
        assert!(
            audit(repo.path(), &["--mode", "advisory", "--policy", &path])
                .status
                .success()
        );
        assert_eq!(report(repo.path())["policy"]["minimum_score"], 100);
    }
}

#[test]
fn missing_optional_policy_defaults_but_invalid_inputs_fail() {
    let repo = fixture("minimum_score = 90\n");
    let path = repo.path().join("agent/audit-policy.toml");
    fs::remove_file(&path).unwrap();
    assert_eq!(
        run_audit(repo.path(), &[])
            .unwrap()
            .policy
            .unwrap()
            .minimum_score,
        85
    );
    for contents in [
        b"minimum_score = -1\n".as_slice(),
        b"minimum_score = 101\n",
        b"[invalid",
        b"\xff\xfe",
    ] {
        fs::write(&path, contents).unwrap();
        rejects_without_replacing_reports(repo.path(), &["--mode", "advisory"], "audit");
    }
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    rejects_without_replacing_reports(repo.path(), &["--mode", "advisory"], "regular file");
}

#[test]
#[cfg(unix)]
fn linked_policy_and_control_directory_are_not_missing_inputs() {
    use std::os::unix::fs::symlink;
    let repo = fixture("minimum_score = 90\n");
    let path = repo.path().join("agent/audit-policy.toml");
    fs::remove_file(&path).unwrap();
    symlink("missing.toml", &path).unwrap();
    rejects_without_replacing_reports(repo.path(), &["--mode", "advisory"], "regular file");
    fs::remove_file(&path).unwrap();
    fs::write(repo.path().join("outside.toml"), "minimum_score = 0\n").unwrap();
    symlink("../outside.toml", &path).unwrap();
    rejects_without_replacing_reports(repo.path(), &["--mode", "advisory"], "regular file");
    fs::rename(
        repo.path().join("agent"),
        repo.path().join("retained-agent"),
    )
    .unwrap();
    symlink("retained-agent", repo.path().join("agent")).unwrap();
    rejects_without_replacing_reports(repo.path(), &["--mode", "advisory"], "control directory");
    assert_eq!(
        fs::read_to_string(repo.path().join("outside.toml")).unwrap(),
        "minimum_score = 0\n"
    );
}

#[test]
fn resolved_policy_rejects_other_roots_and_source_changes() {
    let repo = fixture("minimum_score = 90\n");
    let other = fixture("minimum_score = 90\n");
    let resolve =
        || outcome::resolve_policy(repo.path(), None, None, &[], AuditMode::Standard).unwrap();
    let err = run_audit_timed_with_policy(other.path(), &[], AuditOptions::default(), resolve())
        .unwrap_err();
    assert!(err.to_string().contains("different repository"));
    let before = resolve();
    fs::write(
        repo.path().join("agent/audit-policy.toml"),
        "minimum_score = 95\n",
    )
    .unwrap();
    let err =
        run_audit_timed_with_policy(repo.path(), &[], AuditOptions::default(), before).unwrap_err();
    assert!(err.to_string().contains("changed after resolution"));
}

#[test]
fn repository_metadata_cannot_impersonate_the_auditor_or_schema() {
    let repo = fixture("minimum_score = 85\n");
    let path = repo.path().join("agent/standard-version.toml");
    fs::write(&path, "standard_version = \"0.9.0\"\nauditor_version = \"999.0.0\"\nschema_version = \"999.0.0\"\n").unwrap();
    let report = run_audit(repo.path(), &[]).unwrap();
    assert_eq!(report.auditor_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(report.schema_version, jankurai::model::SCHEMA_VERSION);
    for contents in [
        "[invalid",
        "standard_version = 9\n",
        "auditor_version = false\n",
        "schema_version = \"\"\n",
    ] {
        fs::write(&path, contents).unwrap();
        rejects_without_replacing_reports(
            repo.path(),
            &["--mode", "advisory"],
            "invalid standard version manifest",
        );
    }
}

#[test]
fn explicitly_requested_receipts_must_be_readable_and_nonempty() {
    let repo = fixture("minimum_score = 85\n");
    rejects_without_replacing_reports(
        repo.path(),
        &["--mode", "advisory", "--proof-receipts", "missing"],
        "requested proof receipts",
    );
    fs::create_dir(repo.path().join("receipts")).unwrap();
    rejects_without_replacing_reports(
        repo.path(),
        &["--mode", "advisory", "--proof-receipts", "receipts"],
        "contains no JSON receipts",
    );
    fs::write(repo.path().join("receipts/bad.json"), "{}").unwrap();
    rejects_without_replacing_reports(
        repo.path(),
        &["--mode", "advisory", "--proof-receipts", "receipts"],
        "lane",
    );
    fs::write(repo.path().join("receipts/bad.json"), json!({"lane":"historical", "command":"false", "exit_code":1, "elapsed_ms":1, "artifacts":[]}).to_string()).unwrap();
    assert!(audit(
        repo.path(),
        &["--mode", "advisory", "--proof-receipts", "receipts"]
    )
    .status
    .success());
    assert_eq!(report(repo.path())["proof_receipts"][0]["exit_code"], 1);
}

#[test]
fn forged_success_receipt_never_authorizes_release() {
    let repo = fixture("minimum_score = 0\nfail_on = []\n");
    fs::write(
        repo.path().join("receipt.json"),
        json!({"lane":"release", "command":"true", "exit_code":0, "elapsed_ms":1, "artifacts":[]})
            .to_string(),
    )
    .unwrap();
    let output = audit(
        repo.path(),
        &["--mode", "release", "--proof-receipts", "receipt.json"],
    );
    assert!(!output.status.success());
    let value = report(repo.path());
    assert_eq!(value["decision"]["passed"], false);
    assert_eq!(value["conformance_decision"], "block");
    assert!(value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["problem"]
            .as_str()
            .is_some_and(|text| text.contains("supervised execution"))));
}

#[test]
fn advisory_and_ratchet_share_effective_policy_identity() {
    let repo = fixture("minimum_score = 85\n");
    let mut reports = Vec::new();
    for mode in [AuditMode::Advisory, AuditMode::Ratchet] {
        let policy = outcome::resolve_policy(repo.path(), None, None, &[], mode).unwrap();
        let (report, _) =
            run_audit_timed_with_policy(repo.path(), &[], AuditOptions::default(), policy).unwrap();
        reports.push(report);
    }
    assert_eq!(reports[0].policy_fingerprint, reports[1].policy_fingerprint);
    assert!(!reports[1].decision.as_ref().unwrap().passed);
    assert!(
        !reports[1]
            .decision
            .as_ref()
            .unwrap()
            .ratchet
            .as_ref()
            .unwrap()
            .passed
    );
}

#[test]
fn invalid_changed_paths_cannot_disappear_from_scope() {
    let repo = fixture("minimum_score = 85\n");
    let outside = tempfile::tempdir().unwrap();
    let outside_path = outside.path().join("foreign.rs");
    fs::write(&outside_path, "pub fn foreign() {}\n").unwrap();
    for path in [
        outside_path.to_str().unwrap(),
        "../foreign.rs",
        "src/../../foreign.rs",
    ] {
        rejects_without_replacing_reports(
            repo.path(),
            &["--mode", "advisory", "--changed", path],
            "audited repository",
        );
    }
    // Deletions remain legitimate inputs even though the source no longer exists.
    let value = run_audit(repo.path(), &["removed.rs".into()]).unwrap();
    assert_eq!(value.scope.paths, ["removed.rs"]);
}

#[test]
fn unavailable_git_status_never_claims_a_clean_worktree() {
    let repo = fixture("minimum_score = 85\n");
    fs::write(repo.path().join(".git"), "gitdir: missing-git-directory\n").unwrap();
    let value = run_audit(repo.path(), &[]).unwrap();
    let git = value.git.unwrap();
    assert!(git.head.is_none());
    assert_eq!(git.dirty_worktree, Some(true));
    assert!(value.dirty_worktree);
}

#[test]
fn legacy_baseline_requires_identical_source_and_effective_settings() {
    let repo = fixture("minimum_score = 85\n");
    let original = run_audit(repo.path(), &[]).unwrap();
    let mut historical = serde_json::to_value(&original).unwrap();
    historical["policy_fingerprint"] = json!(format!(
        "sha256:{:x}",
        Sha256::digest(fs::read(repo.path().join("agent/audit-policy.toml")).unwrap())
    ));
    let directory = repo.path().join("target");
    fs::create_dir_all(&directory).unwrap();
    let baseline = directory.join("baseline.json");
    fs::write(&baseline, historical.to_string()).unwrap();
    let result =
        jankurai::audit::baseline::compare_report_to_baseline(&original, &baseline).unwrap();
    assert!(!result.policy_changed);
    assert!(result.passed);

    // The old file-only hash cannot conceal a CLI floor or severity change.
    for (floor, severities) in [(Some(90), vec![]), (None, vec!["medium".to_string()])] {
        let policy =
            outcome::resolve_policy(repo.path(), None, floor, &severities, AuditMode::Ratchet)
                .unwrap();
        let (current, _) =
            run_audit_timed_with_policy(repo.path(), &[], AuditOptions::default(), policy).unwrap();
        let result =
            jankurai::audit::baseline::compare_report_to_baseline(&current, &baseline).unwrap();
        assert!(result.policy_changed);
        assert!(!result.passed);
    }
    let mut incomplete = historical.clone();
    incomplete["policy"]
        .as_object_mut()
        .unwrap()
        .remove("fail_on");
    fs::write(&baseline, incomplete.to_string()).unwrap();
    assert!(
        jankurai::audit::baseline::compare_report_to_baseline(&original, &baseline)
            .unwrap()
            .policy_changed
    );
    fs::write(&baseline, historical.to_string()).unwrap();
    fs::write(
        repo.path().join("agent/audit-policy.toml"),
        "minimum_score = 85\n# source changed\n",
    )
    .unwrap();
    // A policy swapped after the audit cannot acquire the old baseline identity.
    assert!(
        jankurai::audit::baseline::compare_report_to_baseline(&original, &baseline)
            .unwrap()
            .policy_changed
    );
}
