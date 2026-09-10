use jankurai::audit::run_audit;
use serde_json::{json, Value};
use std::{fs, process::Command};

#[test]
fn public_badge_rejects_contradictory_decisions_without_replacing_outputs() {
    let repo = tempfile::tempdir().unwrap();
    fs::write(repo.path().join("README.md"), "# Badge test fixture\n").unwrap();
    let mut report = serde_json::to_value(run_audit(repo.path(), &[]).unwrap()).unwrap();
    let mut finding = report["findings"][0].clone();
    assert!(finding.is_object());
    finding["hardness"] = json!("hard");
    // Synthetic report fixture for the badge validator, not qualification evidence.
    report["score"] = json!(95);
    report["raw_score"] = json!(95);
    report["policy"]["minimum_score"] = json!(85);
    report["dirty_worktree"] = json!(false);
    report["git"]["dirty_worktree"] = json!(false);
    report["git"]["mode"] = json!("full");
    report["scope"] = json!({"mode":"full","paths":[]});
    report["findings"] = json!([]);
    report["caps_applied"] = json!([]);
    report["decision"]["status"] = json!("pass");
    report["decision"]["passed"] = json!(true);
    report["decision"]["minimum_score"] = json!(85);
    report["decision"]["hard_findings"] = json!(0);
    report["decision"]["soft_findings"] = json!(0);
    let source = repo.path().join("score.json");
    let run = |report: &Value, check: bool| {
        fs::write(&source, serde_json::to_vec(report).unwrap()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_jankurai"));
        command.current_dir(repo.path()).args([
            "badge",
            ".",
            "--score",
            "score.json",
            "--no-readme",
        ]);
        if check {
            command.arg("--check");
        }
        command.output().unwrap()
    };
    let positive = run(&report, false);
    assert!(
        positive.status.success(),
        "{}",
        String::from_utf8_lossy(&positive.stderr)
    );
    assert!(run(&report, true).status.success());
    let badge = repo.path().join("agent/jankurai-badge.svg");
    let original = fs::read(&badge).unwrap();
    let mutations = [
        ("/decision/hard_findings", json!(1)),
        ("/decision/passed", json!(false)),
        ("/decision/status", json!("fail")),
        ("/decision/minimum_score", json!(0)),
        ("/policy/minimum_score", json!(100)),
        ("/score", json!(84)),
        ("/score", json!(4294967391_i64)),
        ("/dirty_worktree", json!(true)),
        ("/git/dirty_worktree", json!(true)),
        ("/git/mode", json!("changed")),
        ("/scope/mode", json!("changed")),
        ("/scope/paths", json!(["README.md"])),
    ];
    for (pointer, value) in mutations {
        let mut changed = report.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        for check in [false, true] {
            assert!(
                !run(&changed, check).status.success(),
                "accepted {pointer}, check={check}"
            );
            assert_eq!(
                fs::read(&badge).unwrap(),
                original,
                "rewrote badge on {pointer}"
            );
        }
    }
    // The formerly accepted advisory/explicit-pass/hard-finding contradiction.
    let mut advisory = report.clone();
    advisory["decision"]["status"] = json!("advisory");
    advisory["decision"]["hard_findings"] = json!(1);
    assert!(!run(&advisory, false).status.success());
    assert_eq!(fs::read(&badge).unwrap(), original);
    let mut inconsistent = report.clone();
    inconsistent["findings"] = json!([finding]);
    jankurai::validation::validate_value(
        repo.path(),
        jankurai::validation::ArtifactSchema::RepoScore,
        &inconsistent,
    )
    .unwrap();
    assert!(!run(&inconsistent, false).status.success());
    assert_eq!(fs::read(&badge).unwrap(), original);
}
