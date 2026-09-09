use std::fs;
use std::process::Command;
use tempfile::tempdir;

use jankurai::validation::{self, ArtifactSchema};

fn binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_jankurai")
}

fn write_policy(repo: &std::path::Path) {
    fs::create_dir_all(repo.join("agent")).unwrap();
    fs::write(
        repo.join("agent/security-policy.toml"),
        r#"
schema_version = "1.0.0"
enabled_tools = ["gitleaks", "cargo audit"]
required_tools = []
advisory_tools = ["cargo audit"]

[severity_thresholds]
fail_lane_on = "high"
"#,
    )
    .unwrap();
}

#[test]
fn security_run_writes_valid_evidence_and_log() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("tools")).unwrap();
    write_policy(repo.path());
    fs::write(
        repo.path().join("tools/security-lane.sh"),
        "#!/usr/bin/env bash\necho ok\nexit 0\n",
    )
    .unwrap();

    let evidence_path = repo.path().join("out/evidence.json");
    let status = Command::new(binary_path())
        .arg("security")
        .arg("run")
        .arg(repo.path())
        .arg("--script")
        .arg("tools/security-lane.sh")
        .arg("--out")
        .arg(&evidence_path)
        .status()
        .unwrap();
    assert!(status.success(), "security run failed");

    let text = fs::read_to_string(&evidence_path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    validation::validate_value(repo.path(), ArtifactSchema::SecurityEvidence, &value).unwrap();

    assert_eq!(value["exit_code"], 0);
    assert_eq!(value["lane"], "security");
    assert_eq!(value["wrapper"]["strict"], false);
    assert_eq!(value["policy"]["schema_version"], "1.0.0");
    assert_eq!(value["policy"]["required_tools"], serde_json::json!([]));
    assert_eq!(value["policy"]["profile"], "local");

    let log_rel = value["log_path"].as_str().unwrap();
    let log_abs = repo.path().join(log_rel);
    let log_text = fs::read_to_string(&log_abs).unwrap();
    assert!(!log_text.is_empty());
    assert!(log_text.contains("ok"));

    assert!(
        value["commands"][0]["status"] == "ran",
        "{:?}",
        value["commands"]
    );
}

#[test]
fn security_run_records_non_zero_exit_in_evidence() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("tools")).unwrap();
    write_policy(repo.path());
    fs::write(
        repo.path().join("tools/security-lane.sh"),
        "#!/usr/bin/env bash\necho boom\nexit 7\n",
    )
    .unwrap();

    let evidence_path = repo.path().join("out/evidence.json");
    let output = Command::new(binary_path())
        .arg("security")
        .arg("run")
        .arg(repo.path())
        .arg("--script")
        .arg("tools/security-lane.sh")
        .arg("--out")
        .arg(&evidence_path)
        .output()
        .unwrap();
    assert!(!output.status.success(), "expected non-zero process exit");

    let text = fs::read_to_string(&evidence_path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    validation::validate_value(repo.path(), ArtifactSchema::SecurityEvidence, &value).unwrap();

    assert_eq!(value["exit_code"], 7);
    assert!(value["commands"][0]["status"] == "failed");
}

#[test]
fn security_run_collects_jankurai_security_step_lines() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("tools")).unwrap();
    write_policy(repo.path());
    let script = r#"#!/usr/bin/env bash
printf '%s\n' 'jankurai-security-step={"label":"step-a","tool":"t1","shell_command":"true","status":"ran","advisory":false,"exit_code":0}'
printf '%s\n' 'jankurai-security-step={"label":"step-b","shell_command":"true","status":"skipped","advisory":true}'
exit 0
"#;
    fs::write(repo.path().join("tools/security-lane.sh"), script).unwrap();

    let evidence_path = repo.path().join("out/evidence.json");
    let status = Command::new(binary_path())
        .arg("security")
        .arg("run")
        .arg(repo.path())
        .arg("--script")
        .arg("tools/security-lane.sh")
        .arg("--out")
        .arg(&evidence_path)
        .status()
        .unwrap();
    assert!(status.success(), "security run failed");

    let text = fs::read_to_string(&evidence_path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    validation::validate_value(repo.path(), ArtifactSchema::SecurityEvidence, &value).unwrap();

    let cmds = value["commands"].as_array().unwrap();
    assert_eq!(cmds.len(), 2, "{cmds:?}");
    assert_eq!(cmds[0]["label"], "step-a");
    assert_eq!(cmds[0]["tool"], "t1");
    assert_eq!(cmds[0]["status"], "ran");
    assert_eq!(cmds[0]["required_by_policy"], true);
    assert_eq!(cmds[0]["blocking"], false);
    assert_eq!(cmds[1]["label"], "step-b");
    assert_eq!(cmds[1]["status"], "skipped");
    assert_eq!(cmds[1]["advisory"], true);
    assert_eq!(cmds[1]["required_by_policy"], false);
    assert_eq!(cmds[1]["blocking"], false);
}

#[test]
fn security_ci_profile_blocks_skipped_required_tools() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("tools")).unwrap();
    fs::create_dir_all(repo.path().join("agent")).unwrap();
    fs::write(
        repo.path().join("agent/security-policy.toml"),
        r#"
schema_version = "1.0.0"

[profiles.ci]
enabled_tools = ["gitleaks"]
required_tools = ["gitleaks"]
advisory_tools = []

[severity_thresholds]
fail_lane_on = "high"
"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("tools/security-lane.sh"),
        "#!/usr/bin/env bash\necho ok\nexit 0\n",
    )
    .unwrap();

    let evidence_path = repo.path().join("out/evidence.json");
    let output = Command::new(binary_path())
        .arg("security")
        .arg("run")
        .arg(repo.path())
        .arg("--profile")
        .arg("ci")
        .arg("--strict")
        .arg("--script")
        .arg("tools/security-lane.sh")
        .arg("--out")
        .arg(&evidence_path)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&evidence_path).unwrap()).unwrap();
    validation::validate_value(repo.path(), ArtifactSchema::SecurityEvidence, &value).unwrap();
    assert_eq!(value["exit_code"], 1);
    let commands = value["commands"].as_array().unwrap();
    let gitleaks = commands
        .iter()
        .find(|command| command["tool"] == "gitleaks")
        .expect("gitleaks command evidence");
    assert_eq!(gitleaks["blocking"], true);
}
// These wrappers exercise record intake only; they do not claim scanner execution.
fn run_fixture_records(
    records: &str,
    policy: &str,
    extra_script: &str,
) -> (std::process::Output, serde_json::Value) {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("tools")).unwrap();
    fs::create_dir_all(repo.path().join("agent")).unwrap();
    fs::write(repo.path().join("agent/security-policy.toml"), policy).unwrap();
    fs::write(repo.path().join("records.txt"), records).unwrap();
    fs::write(
        repo.path().join("tools/security-lane.sh"),
        format!("#!/usr/bin/env bash\ncat records.txt\nprintf '\\n'\n{extra_script}\nexit 0\n"),
    )
    .unwrap();
    let evidence_path = repo.path().join("out/evidence.json");
    let output = Command::new(binary_path())
        .arg("security")
        .arg("run")
        .arg(repo.path())
        .args([
            "--profile",
            "ci",
            "--strict",
            "--script",
            "tools/security-lane.sh",
            "--out",
        ])
        .arg(&evidence_path)
        .output()
        .unwrap();
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&evidence_path).unwrap()).unwrap();
    validation::validate_value(repo.path(), ArtifactSchema::SecurityEvidence, &value).unwrap();
    (output, value)
}

fn fixture_record(label: &str, status: &str, code: Option<i32>) -> String {
    let mut row = serde_json::json!({
        "label": label, "tool": "fixture-scan", "shell_command": "fixture-scan",
        "status": status, "advisory": true,
    });
    if let Some(code) = code {
        row["exit_code"] = code.into();
    }
    format!("jankurai-security-step={row}")
}

#[test]
fn security_run_blocks_invalid_records_even_after_required_success() {
    let policy = "[profiles.ci]\nrequired_tools = ['fixture-scan']\n";
    let success = fixture_record("good", "ran", Some(0));
    for invalid in [
        "jankurai-security-step={".to_string(),
        "jankurai-security-step={}".to_string(),
        fixture_record("bad", "ran", Some(42)),
        fixture_record("bad", "ran", None),
        fixture_record("bad", "failed", Some(0)),
        fixture_record("bad", "skipped", Some(0)),
        fixture_record("bad", "unknown", Some(0)),
    ] {
        for records in [
            format!("{success}\n{invalid}"),
            format!("{invalid}\n{success}"),
        ] {
            let (output, value) = run_fixture_records(&records, policy, "");
            assert!(!output.status.success(), "{records}");
            assert_eq!(value["exit_code"], 1);
            assert!(value["commands"].as_array().unwrap().iter().any(|row| {
                row["blocking"] == true
                    && row["label"]
                        .as_str()
                        .unwrap()
                        .starts_with("invalid-security-record")
            }));
        }
    }
}

#[test]
fn security_run_blocks_conflicting_advisory_records() {
    let policy = "[profiles.ci]\nadvisory_tools = ['fixture-scan']\n";
    let success = fixture_record("same", "ran", Some(0));
    let failure = fixture_record("same", "failed", Some(42));
    for records in [
        format!("{success}\n{failure}"),
        format!("{failure}\n{success}"),
    ] {
        let (output, value) = run_fixture_records(&records, policy, "");
        assert!(!output.status.success());
        assert_eq!(value["exit_code"], 1);
    }
}

#[test]
fn security_run_preserves_valid_standalone_advisory_outcomes() {
    let policy = "[profiles.ci]\nadvisory_tools = ['fixture-scan']\n";
    for (status, code) in [("ran", Some(0)), ("failed", Some(42)), ("skipped", None)] {
        let (output, value) =
            run_fixture_records(&fixture_record("scan", status, code), policy, "");
        assert!(output.status.success(), "{:?}", output);
        assert_eq!(value["exit_code"], 0);
        assert_eq!(value["commands"][0]["blocking"], false);
    }
}

#[test]
fn security_run_one_of_requires_a_successful_member() {
    let policy = "[profiles.ci]\nadvisory_tools = ['fixture-scan']\nrequire_one_of = [['fixture-scan', 'other-scan']]\n";
    for (status, code, expected_success) in [
        ("ran", Some(0), true),
        ("failed", Some(42), false),
        ("skipped", None, false),
    ] {
        let (output, value) =
            run_fixture_records(&fixture_record("scan", status, code), policy, "");
        assert_eq!(output.status.success(), expected_success);
        assert_eq!(value["exit_code"], if expected_success { 0 } else { 1 });
    }
}

#[test]
fn security_run_required_failure_stays_blocking_after_a_later_success() {
    let policy = "[profiles.ci]\nrequired_tools = ['fixture-scan']\n";
    let records = format!(
        "{}\n{}",
        fixture_record("first", "failed", Some(42)),
        fixture_record("second", "ran", Some(0)),
    );
    let (output, value) = run_fixture_records(&records, policy, "");
    assert!(!output.status.success());
    assert_eq!(value["exit_code"], 1);
    assert_eq!(value["commands"][0]["blocking"], true);
    assert_eq!(value["commands"][1]["blocking"], false);
}

#[test]
fn security_run_rejects_non_utf8_wrapper_output() {
    let policy = "[profiles.ci]\nrequired_tools = ['fixture-scan']\n";
    for script in ["printf '\\377'", "printf '\\377' >&2"] {
        let (output, value) =
            run_fixture_records(&fixture_record("scan", "ran", Some(0)), policy, script);
        assert!(!output.status.success());
        assert_eq!(value["exit_code"], 1);
        assert!(value["commands"].as_array().unwrap().iter().any(|row| {
            row["blocking"] == true && row["label"].as_str().unwrap().contains("non-UTF-8")
        }));
    }
}
