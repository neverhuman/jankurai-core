use jankurai::audit::run_audit;
use jankurai::commands::witness::{build_witness, WitnessArgs};
use jankurai::validation::{self, ArtifactSchema};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::tempdir;

fn seed(repo: &Path) {
    fs::create_dir_all(repo.join("agent")).unwrap();
    fs::create_dir_all(repo.join("docs")).unwrap();
    fs::create_dir_all(repo.join("target/jankurai")).unwrap();
    for (path, text) in [
        ("AGENTS.md", "Read agent/JANKURAI_STANDARD.md first.\n"),
        ("README.md", "# fixture\n"),
        ("agent/JANKURAI_STANDARD.md", "Standard version: `0.9.0`\n"),
        (
            "docs/agent-native-standard.md",
            "Standard version: `0.9.0`\n",
        ),
        (
            "agent/audit-policy.toml",
            "minimum_score = 0\nfail_on = [\"critical\"]\nadvisory_on = [\"medium\", \"low\"]\n",
        ),
    ] {
        fs::write(repo.join(path), text).unwrap();
    }
}

fn args(repo: &Path, baseline: Option<&Path>) -> WitnessArgs {
    WitnessArgs {
        repo: repo.to_path_buf(),
        changed: vec![],
        changed_from: None,
        baseline: baseline.map(|path| path.display().to_string()),
        proof_receipts: None,
        out: repo
            .join("target/jankurai/witness.json")
            .display()
            .to_string(),
        md: repo
            .join("target/jankurai/witness.md")
            .display()
            .to_string(),
    }
}

fn baseline(repo: &Path, path: &Path) -> Value {
    let report = run_audit(repo, &[]).unwrap();
    let value = serde_json::to_value(&report).unwrap();
    fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    value
}

fn cli(repo: &Path, baseline: Option<&Path>, output: &Path) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_jankurai"));
    command
        .arg("witness")
        .arg(repo)
        .arg("--out")
        .arg(output.join("witness.json"))
        .arg("--md")
        .arg(output.join("witness.md"));
    if let Some(baseline) = baseline {
        command.arg("--baseline").arg(baseline);
    }
    command.output().unwrap()
}

fn witness(repo: &Path, output: &Path) -> Value {
    let value = serde_json::from_slice(&fs::read(output.join("witness.json")).unwrap()).unwrap();
    validation::validate_value(repo, ArtifactSchema::MergeWitness, &value).unwrap();
    assert!(output.join("witness.md").is_file());
    value
}

#[test]
fn full_baseline_can_pass_and_review_exits_nonzero_after_writing_artifacts() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let output = tempdir().unwrap();
    let path = output.path().join("baseline.json");
    let source = baseline(&repo, &path);
    assert_eq!(source["scope"]["mode"], "full");
    assert_eq!(source["conformance_decision"], "pass");
    let accepted = cli(&repo, Some(&path), output.path());
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let value = witness(&repo, output.path());
    assert_eq!(value["decision"], "pass");
    assert_eq!(value["conformance_decision"], "pass");
    assert_eq!(value["observed_conformance_level"], "HL3");
    let review = cli(&repo, None, output.path());
    assert!(!review.status.success());
    assert_eq!(witness(&repo, output.path())["decision"], "review");
}

#[test]
fn carried_high_findings_block_weak_policy_witness_and_remain_visible() {
    let repo = tempdir().unwrap();
    seed(repo.path());
    let path = repo.path().join("target/jankurai/baseline.json");
    let source = baseline(repo.path(), &path);
    assert_eq!(source["decision"]["passed"], true);
    let high = source["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| matches!(finding["severity"].as_str(), Some("high" | "critical")))
        .count();
    assert!(high > 0);
    let output = cli(
        repo.path(),
        Some(&path),
        &repo.path().join("target/jankurai"),
    );
    assert!(!output.status.success());
    let value = witness(repo.path(), &repo.path().join("target/jankurai"));
    assert_eq!(value["decision"], "block");
    assert_eq!(value["conformance_decision"], "block");
    assert_ne!(value["observed_conformance_level"], "HL3");
    assert!(!value["conformance_blockers"].as_array().unwrap().is_empty());
    let carried_high = value["carried_findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| matches!(finding["severity"].as_str(), Some("high" | "critical")))
        .count();
    assert_eq!(carried_high, high);
    for finding in source["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| matches!(finding["severity"].as_str(), Some("high" | "critical")))
    {
        let rule = finding["rule_id"]
            .as_str()
            .unwrap_or_else(|| finding["check_id"].as_str().unwrap());
        let path = finding["path"].as_str().unwrap();
        assert!(value["conformance_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|reason| reason.contains(rule) && reason.contains(path)));
    }
}

#[test]
fn unmapped_route_is_visible_even_when_it_has_no_required_lane() {
    let repo = tempdir().unwrap();
    seed(repo.path());
    fs::create_dir(repo.path().join("src")).unwrap();
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn api() -> bool { true }\n",
    )
    .unwrap();
    let mut input = args(repo.path(), None);
    input.changed.push("src/lib.rs".into());
    let value = build_witness(&input).unwrap();
    assert_eq!(value.route_decisions[0].decision, "block");
    assert!(value.required_lanes.is_empty());
    assert!(value
        .missing_evidence
        .iter()
        .any(|reason| reason.contains("route for `src/lib.rs`")));
    assert!(value
        .conformance_blockers
        .iter()
        .any(|reason| reason.contains("route for `src/lib.rs`")));
    assert_eq!(value.decision, "block");
}

#[test]
fn semantic_obligations_require_receipts_even_when_artifact_claims_satisfied() {
    let repo = tempdir().unwrap();
    seed(repo.path());
    fs::create_dir(repo.path().join("src")).unwrap();
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn api() -> bool { true }\n",
    )
    .unwrap();
    fs::write(repo.path().join("agent/owner-map.json"), r#"{"workspace":"fixture","owners":{"src/":"tools","agent/":"agent","target/":"workspace"}}"#).unwrap();
    fs::write(repo.path().join("agent/test-map.json"), r#"{"workspace":"fixture","tests":{"src/":{"command":"cargo test -p fixture","purpose":"rust"},"agent/":{"command":"just score","purpose":"agent"}}}"#).unwrap();
    fs::write(repo.path().join("agent/proof-lanes.toml"), "[[lane]]\nname = \"proofmark-rust\"\ncommand = \"cargo test -p fixture\"\npurpose = \"proofmark\"\n").unwrap();
    let run = |arguments: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_jankurai"))
            .current_dir(repo.path())
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run(&[
        "proofbind",
        "verify",
        repo.path().to_str().unwrap(),
        "--changed",
        "src/lib.rs",
    ]);
    let obligation_path = repo
        .path()
        .join("target/jankurai/proofbind/obligations.json");
    let mut obligations: Value =
        serde_json::from_slice(&fs::read(&obligation_path).unwrap()).unwrap();
    assert_eq!(obligations["obligations"].as_array().unwrap().len(), 1);
    obligations["obligations"][0]["satisfied"] = json!(true);
    obligations["summary"]["missing"] = json!(0);
    obligations["summary"]["verdict"] = json!("pass");
    fs::write(&obligation_path, serde_json::to_vec(&obligations).unwrap()).unwrap();
    let mut input = args(repo.path(), None);
    input.changed.push("src/lib.rs".into());
    let missing = build_witness(&input).unwrap();
    assert_eq!(missing.proofbind.missing_obligation_count, 1);
    assert!(missing
        .conformance_blockers
        .iter()
        .any(|reason| reason.contains("semantic proof obligation")));
    fs::write(
        repo.path().join("coverage.lcov"),
        "TN:\nSF:src/lib.rs\nDA:1,1\nend_of_record\n",
    )
    .unwrap();
    run(&[
        "proofmark",
        "rust",
        repo.path().to_str().unwrap(),
        "--changed",
        "src/lib.rs",
        "--coverage",
        "coverage.lcov",
    ]);
    let receipt_path = repo
        .path()
        .join("target/jankurai/proofmark/proof-receipt.json");
    input.proof_receipts = Some(receipt_path.display().to_string());
    let satisfied = build_witness(&input).unwrap();
    assert_eq!(satisfied.proofbind.missing_obligation_count, 0);
    assert_eq!(satisfied.proofbind.satisfied_obligation_count, 1);
    assert!(!satisfied
        .conformance_blockers
        .iter()
        .any(|reason| reason.contains("semantic proof obligation")));
    let mut receipt: Value = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    receipt["exit_code"] = json!(1);
    fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    let failed = build_witness(&input).unwrap();
    assert_eq!(failed.proofbind.missing_obligation_count, 1);
    assert!(failed.available_proof_receipts.is_empty());
}

#[test]
fn malformed_baselines_are_rejected_and_valid_score_regression_is_reported() {
    let repo = tempdir().unwrap();
    seed(repo.path());
    let path = repo.path().join("target/jankurai/baseline.json");
    let original = baseline(repo.path(), &path);
    assert!(build_witness(&args(repo.path(), Some(&path))).is_ok());
    for (field, bad) in [
        ("score", Value::Null),
        ("score", json!("bad")),
        ("score", json!(101)),
        ("findings", json!({})),
        ("caps_applied", json!([1])),
        ("report_fingerprint", json!("invalid")),
        ("input_fingerprint", json!("invalid")),
        ("scope", json!({"mode":"changed","paths":["src/lib.rs"]})),
    ] {
        let mut value = original.clone();
        value[field] = bad;
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            build_witness(&args(repo.path(), Some(&path))).is_err(),
            "accepted malformed {field}"
        );
    }
    let mut regression = original.clone();
    let score = original["score"].as_i64().unwrap();
    assert!(score < 100);
    regression["score"] = json!(score + 1);
    fs::write(&path, serde_json::to_vec(&regression).unwrap()).unwrap();
    let value = build_witness(&args(repo.path(), Some(&path))).unwrap();
    assert_eq!(value.score_delta, Some(-1));
    assert_eq!(value.decision, "ratchet_fail");
}

#[test]
fn changed_from_errors_do_not_become_an_empty_route_set() {
    let repo = tempdir().unwrap();
    seed(repo.path());
    let mut input = args(repo.path(), None);
    input.changed_from = Some("HEAD".into());
    assert!(build_witness(&input).is_err());
    for arguments in [
        vec!["init", "--quiet"],
        vec![
            "-c",
            "user.name=Witness Fixture",
            "-c",
            "user.email=witness@example.invalid",
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "fixture",
        ],
    ] {
        let output = Command::new("git")
            .current_dir(repo.path())
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(build_witness(&input).unwrap().changed_paths.is_empty());
    let changed = "changed\npath.md";
    fs::write(repo.path().join(changed), "# Changed path\n").unwrap();
    for arguments in [
        vec!["add", "--", changed],
        vec![
            "-c",
            "user.name=Witness Fixture",
            "-c",
            "user.email=witness@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "changed path",
        ],
    ] {
        let output = Command::new("git")
            .current_dir(repo.path())
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    input.changed_from = Some("HEAD~1".into());
    assert_eq!(build_witness(&input).unwrap().changed_paths, [changed]);
    for invalid in ["missing-witness-base", "--output=unexpected"] {
        input.changed_from = Some(invalid.into());
        assert!(build_witness(&input).is_err());
    }
    assert!(!repo.path().join("unexpected").exists());
}
