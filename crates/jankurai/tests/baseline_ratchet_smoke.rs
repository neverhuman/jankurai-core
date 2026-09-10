use jankurai::audit::run_audit;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_jankurai")
}

fn write_pass_repo(repo: &Path) {
    fs::write(
        repo.join("AGENTS.md"),
        "Read agent/JANKURAI_STANDARD.md first.\n",
    )
    .unwrap();
    fs::write(repo.join("README.md"), "# fixture\n").unwrap();
    fs::write(
        repo.join("Justfile"),
        "fast:\n    echo ok\ncheck:\n    echo ok\n",
    )
    .unwrap();
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

fn write_report_baseline(repo: &Path, path: &Path) -> serde_json::Value {
    let report = run_audit(repo, &[]).unwrap();
    let value = serde_json::to_value(&report).unwrap();
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
    )
    .unwrap();
    value
}

fn ratchet(repo: &Path, baseline: &Path) -> std::process::Output {
    Command::new(binary_path())
        .arg("audit")
        .arg(repo)
        .arg("--mode")
        .arg("ratchet")
        .arg("--baseline")
        .arg(baseline)
        .arg("--json")
        .arg(repo.join("target/jankurai/repo-score.json"))
        .arg("--md")
        .arg(repo.join("target/jankurai/repo-score.md"))
        .arg("--no-score-history")
        .output()
        .unwrap()
}

#[test]
fn missing_baseline_in_ratchet_errors() {
    let repo = tempdir().unwrap();
    write_pass_repo(repo.path());

    let output = Command::new(binary_path())
        .arg("audit")
        .arg(repo.path())
        .arg("--mode")
        .arg("ratchet")
        .output()
        .unwrap();

    assert!(!output.status.success());
}

#[test]
fn baseline_missing_score_errors_instead_of_falling_back() {
    let repo = tempdir().unwrap();
    write_pass_repo(repo.path());
    let baseline = repo.path().join("baseline.json");
    fs::write(&baseline, "{}\n").unwrap();

    let output = ratchet(repo.path(), &baseline);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing required integer `score`"));
}

#[test]
fn score_regression_fails_ratchet() {
    let repo = tempdir().unwrap();
    write_pass_repo(repo.path());
    let baseline = repo.path().join("baseline.json");
    let mut value = write_report_baseline(repo.path(), &baseline);
    let score = value["score"].as_i64().unwrap();
    assert!(score < 100);
    value["score"] = serde_json::json!(score + 1);
    fs::write(
        &baseline,
        format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
    )
    .unwrap();

    let output = ratchet(repo.path(), &baseline);

    assert!(!output.status.success());
}

#[test]
fn new_cap_fails_ratchet_even_at_same_score() {
    let repo = tempdir().unwrap();
    write_pass_repo(repo.path());
    fs::remove_file(repo.path().join("Justfile")).unwrap();
    let baseline = repo.path().join("baseline.json");
    let mut value = write_report_baseline(repo.path(), &baseline);
    value["caps_applied"] = serde_json::json!([]);
    fs::write(
        &baseline,
        format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
    )
    .unwrap();

    let output = ratchet(repo.path(), &baseline);

    assert!(!output.status.success());
}

#[test]
fn policy_fingerprint_drift_fails_ratchet() {
    let repo = tempdir().unwrap();
    write_pass_repo(repo.path());
    let baseline = repo.path().join("baseline.json");
    let mut value = write_report_baseline(repo.path(), &baseline);
    value["policy_fingerprint"] = serde_json::json!(
        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    );
    fs::write(
        &baseline,
        format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
    )
    .unwrap();

    let output = ratchet(repo.path(), &baseline);

    assert!(!output.status.success());
}

#[test]
fn baseline_scores_are_bounded_before_comparison() {
    use jankurai::audit::baseline::compare_report_to_baseline;
    use serde_json::json;

    let repo = tempdir().unwrap();
    write_pass_repo(repo.path());
    let current = run_audit(repo.path(), &[]).unwrap();
    let baseline = repo.path().join("baseline.json");
    let original = serde_json::to_value(&current).unwrap();
    fs::write(&baseline, original.to_string()).unwrap();
    assert!(
        compare_report_to_baseline(&current, &baseline)
            .unwrap()
            .passed
    );
    for score in [
        json!(-1),
        json!(i32::MIN),
        json!(101),
        json!(u64::MAX),
        json!(85.5),
        json!("85"),
        json!(null),
    ] {
        let mut value = original.clone();
        value["score"] = score.clone();
        fs::write(&baseline, value.to_string()).unwrap();
        assert!(
            compare_report_to_baseline(&current, &baseline).is_err(),
            "accepted {score}"
        );
    }
    fs::write(&baseline, original.to_string()).unwrap();
    for score in [i32::MIN, -1, 101, i32::MAX] {
        let mut invalid = current.clone();
        invalid.score = score;
        assert!(compare_report_to_baseline(&invalid, &baseline).is_err());
    }
}

#[test]
fn malformed_baseline_fields_cannot_disappear_from_comparison() {
    use jankurai::audit::baseline::compare_report_to_baseline;
    use serde_json::json;

    let repo = tempdir().unwrap();
    write_pass_repo(repo.path());
    let current = run_audit(repo.path(), &[]).unwrap();
    let baseline = repo.path().join("baseline.json");
    let original = serde_json::to_value(&current).unwrap();
    for (field, invalid) in [
        ("report_fingerprint", json!("sha256:pending")),
        ("input_fingerprint", json!("not a digest")),
        (
            "policy_fingerprint",
            json!(format!("sha256:{}", "A".repeat(64))),
        ),
        ("caps_applied", json!([""])),
        ("caps_applied", json!([null])),
        ("findings", json!([null])),
        ("findings", json!([{}])),
        ("findings", json!([{"severity": "unknown"}])),
        (
            "findings",
            json!([{"severity": "medium", "hardness": "unknown"}]),
        ),
        ("findings", json!([{"severity": "high"}])),
        (
            "findings",
            json!([{"severity": "critical", "fingerprint": ""}]),
        ),
        (
            "findings",
            json!([{"severity": "high", "fingerprint": "not a digest"}]),
        ),
    ] {
        let mut value = original.clone();
        value[field] = invalid.clone();
        fs::write(&baseline, value.to_string()).unwrap();
        assert!(
            compare_report_to_baseline(&current, &baseline).is_err(),
            "accepted {field}: {invalid}"
        );
    }
    // Historical soft findings need no hardness declaration or hard-finding identity.
    let mut historical = original;
    historical["findings"] = json!([{"severity": "medium"}]);
    fs::write(&baseline, historical.to_string()).unwrap();
    assert!(compare_report_to_baseline(&current, &baseline).is_ok());
}

#[test]
fn ambiguous_baselines_fail_without_replacing_prior_reports() {
    let repo = tempdir().unwrap();
    write_pass_repo(repo.path());
    let current = run_audit(repo.path(), &[]).unwrap();
    let original = serde_json::to_value(&current).unwrap();
    let baseline = repo.path().join("baseline.json");
    let report_dir = repo.path().join("target/jankurai");
    fs::create_dir_all(&report_dir).unwrap();
    fs::write(report_dir.join("repo-score.json"), "prior JSON report\n").unwrap();
    fs::write(report_dir.join("repo-score.md"), "prior Markdown report\n").unwrap();

    let top_level = format!("{{\"score\":0,{}", &original.to_string()[1..]);
    let mut nested = original.clone();
    nested["findings"] = serde_json::json!([{"severity": "medium"}]);
    let nested = nested.to_string().replace(
        "\"severity\":\"medium\"",
        "\"severity\":\"high\",\"\\u0073everity\":\"medium\"",
    );
    for text in [top_level, nested] {
        fs::write(&baseline, text).unwrap();
        let output = ratchet(repo.path(), &baseline);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate JSON object key"));
        assert_eq!(
            fs::read_to_string(report_dir.join("repo-score.json")).unwrap(),
            "prior JSON report\n"
        );
        assert_eq!(
            fs::read_to_string(report_dir.join("repo-score.md")).unwrap(),
            "prior Markdown report\n"
        );
    }
}

#[test]
fn baseline_reader_rejects_empty_oversized_and_nonregular_inputs() {
    use jankurai::audit::baseline::compare_report_to_baseline;

    let repo = tempdir().unwrap();
    write_pass_repo(repo.path());
    let current = run_audit(repo.path(), &[]).unwrap();
    let baseline = repo.path().join("baseline.json");
    let file = fs::File::create(&baseline).unwrap();
    assert!(compare_report_to_baseline(&current, &baseline)
        .unwrap_err()
        .to_string()
        .contains("nonempty regular file"));
    file.set_len(64 * 1024 * 1024 + 1).unwrap();
    assert!(compare_report_to_baseline(&current, &baseline)
        .unwrap_err()
        .to_string()
        .contains("no larger than 64 MiB"));
    drop(file);
    fs::remove_file(&baseline).unwrap();
    fs::create_dir(&baseline).unwrap();
    assert!(compare_report_to_baseline(&current, &baseline)
        .unwrap_err()
        .to_string()
        .contains("regular file"));
    fs::remove_dir(&baseline).unwrap();
    #[cfg(unix)]
    {
        let target = repo.path().join("accepted.json");
        let bytes = serde_json::to_vec(&current).unwrap();
        fs::write(&target, &bytes).unwrap();
        std::os::unix::fs::symlink(&target, &baseline).unwrap();
        assert!(compare_report_to_baseline(&current, &baseline)
            .unwrap_err()
            .to_string()
            .contains("regular file"));
        assert_eq!(fs::read(&target).unwrap(), bytes);
    }
}
