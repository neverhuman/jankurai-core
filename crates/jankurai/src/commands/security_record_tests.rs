use super::*;

fn record(label: &str, status: &str, exit_code: Option<i32>, advisory: bool) -> String {
    let mut value = serde_json::json!({
        "label": label,
        "tool": "fixture-scan",
        "shell_command": "fixture-scan",
        "status": status,
        "advisory": advisory,
    });
    if let Some(code) = exit_code {
        value["exit_code"] = code.into();
    }
    format!("jankurai-security-step={value}")
}

fn commands(log: &str, policy: &SecurityProfilePolicy) -> Vec<SecurityLaneStep> {
    let mut commands = parse_script_steps(log)
        .into_iter()
        .map(|step| enrich_step(step, policy))
        .collect();
    append_missing_required_steps(&mut commands, policy);
    commands
}

fn assert_invalid(log: &str) {
    let policy = SecurityProfilePolicy {
        advisory_tools: vec!["fixture-scan".into()],
        ..Default::default()
    };
    let commands = commands(log, &policy);
    assert!(commands.iter().any(|step| step.blocking), "{log}");
    assert!(commands.iter().any(|step| {
        step.label.starts_with("invalid-security-record")
            && step.tool.is_none()
            && step.required_by_policy
            && !step.advisory
    }));
}

#[test]
fn malformed_records_never_disappear_or_become_advisory() {
    for payload in [
        "",
        "{",
        "null",
        "[]",
        "{}",
        r#"{"label":"a","shell_command":"scan","status":"ran","exit_code":"0"}"#,
        r#"{"label":"a","shell_command":"scan","status":"ran","exit_code":0,"exit_code":42}"#,
        r#"{"label":"a","shell_command":"scan","status":"ran","exit_code":0} trailing"#,
        r#"{"label":"a","shell_command":"scan","status":"ran","exit_code":0,"advisory":"true"}"#,
        r#"{"label":"a","shell_command":"scan","status":"ran","exit_code":2147483648}"#,
        r#"{"label":"a","shell_command":"scan","status":"ran","exit_code":0,"tool":4}"#,
    ] {
        assert_invalid(&format!("jankurai-security-step={payload}"));
    }
}

#[test]
fn required_success_cannot_hide_a_malformed_record_in_either_order() {
    let success = record("scan", "ran", Some(0), false);
    for log in [
        format!("{success}\njankurai-security-step={{"),
        format!("jankurai-security-step={{\n{success}"),
    ] {
        let policy = SecurityProfilePolicy {
            required_tools: vec!["fixture-scan".into()],
            ..Default::default()
        };
        let commands = commands(&log, &policy);
        assert!(commands.iter().any(|step| step.blocking));
        assert!(commands
            .iter()
            .any(|step| step.status == "ran" && !step.blocking));
    }
}

#[test]
fn contradictory_and_incomplete_outcomes_are_invalid_even_when_advisory() {
    for (status, code) in [
        ("ran", Some(42)),
        ("ran", None),
        ("failed", Some(0)),
        ("failed", None),
        ("skipped", Some(0)),
        ("skipped", Some(42)),
        ("success", Some(0)),
        ("", None),
    ] {
        assert_invalid(&record("scan", status, code, true));
    }
}

#[test]
fn empty_record_identities_are_invalid() {
    let success = record("scan", "ran", Some(0), true);
    for (field, value) in [("label", " "), ("shell_command", ""), ("tool", " \t")] {
        let mut parsed: serde_json::Value =
            serde_json::from_str(success.split_once('=').unwrap().1).unwrap();
        parsed[field] = value.into();
        assert_invalid(&format!("jankurai-security-step={parsed}"));
    }
}

#[test]
fn duplicate_step_outcomes_cannot_be_rewritten_in_either_order() {
    let success = record("same-step", "ran", Some(0), true);
    let failure = record("same-step", "failed", Some(42), true);
    assert_invalid(&format!("{success}\n{failure}"));
    assert_invalid(&format!("{failure}\n{success}"));
}

#[test]
fn duplicate_step_identity_and_policy_cannot_be_rewritten() {
    let success = record("same-step", "ran", Some(0), true);
    for (field, value) in [
        ("tool", serde_json::json!("other-tool")),
        ("shell_command", serde_json::json!("other-command")),
        ("advisory", serde_json::json!(false)),
    ] {
        let mut parsed: serde_json::Value =
            serde_json::from_str(success.split_once('=').unwrap().1).unwrap();
        parsed[field] = value;
        assert_invalid(&format!("{success}\njankurai-security-step={parsed}"));
    }
}

#[test]
fn identical_duplicate_steps_retain_valid_outcomes() {
    let success = record("scan", "ran", Some(0), false);
    let commands = commands(&format!("{success}\n{success}"), &Default::default());
    assert_eq!(commands.len(), 2);
    assert!(commands.iter().all(|step| !step.blocking));
}

#[test]
fn separate_advisory_invocations_are_not_conflicting_records() {
    let policy = SecurityProfilePolicy {
        advisory_tools: vec!["fixture-scan".into()],
        require_one_of: vec![vec!["fixture-scan".into()]],
        ..Default::default()
    };
    let log = format!(
        "{}\n{}",
        record("scan-a", "failed", Some(42), true),
        record("scan-b", "ran", Some(0), true),
    );
    let commands = commands(&log, &policy);
    assert_eq!(commands.len(), 2);
    assert!(commands.iter().all(|step| !step.blocking));
}

#[test]
fn standalone_advisory_failures_and_skips_remain_nonblocking() {
    for (status, code) in [("failed", Some(42)), ("skipped", None)] {
        let commands = commands(&record("scan", status, code, true), &Default::default());
        assert_eq!(commands.len(), 1);
        assert!(!commands[0].blocking);
    }
}

#[test]
fn no_markers_preserves_ordinary_wrapper_fallback() {
    assert!(parse_script_steps("tool output\nno security step records\n").is_empty());
}

#[test]
fn truncated_or_malformed_marker_prefixes_are_invalid() {
    for line in [
        "jankurai-security-step",
        "jankurai-security-step {}",
        "jankurai-security-step ={}",
    ] {
        assert_invalid(line);
    }
}
