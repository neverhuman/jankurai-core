use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

#[test]
fn arbitrary_commands_and_repository_declarations_cannot_mint_coverage() {
    for lane in [
        "required",
        "fast",
        "audit",
        "security",
        "contract",
        "db",
        "db-migration-analyze",
        "web",
        "ux-qa",
        "observability",
        "renamed-required",
    ] {
        for command in [
            "echo verified",
            "true",
            "printf arbitrary > outcome",
            "false",
        ] {
            let repo = tempfile::tempdir().unwrap();
            fs::create_dir(repo.path().join("agent")).unwrap();
            fs::write(repo.path().join("input.rs"), "pub fn changed() {}\n").unwrap();
            fs::write(
                repo.path().join("agent/owner-map.json"),
                json!({"owners":{"input.rs":"tests"}}).to_string(),
            )
            .unwrap();
            fs::write(
                repo.path().join("agent/test-map.json"),
                json!({"tests":{"input.rs":{"command":command,"purpose":"exercise outcome"}}})
                    .to_string(),
            )
            .unwrap();
            // Repository declarations describe intent; they do not authorize producers.
            fs::write(repo.path().join("agent/proof-lanes.toml"), format!(
                "[[lane]]\nname = {lane:?}\ncommand = {command:?}\npurpose = 'exercise outcome'\nrules_covered = ['HLT-008-FALSE-GREEN-RISK', 'HLT-024-AGENT-TOOL-SUPPLY-GAP']\n",
            )).unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_jankurai"))
                .current_dir(repo.path())
                .args(["prove", ".", "--changed", "input.rs"])
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                command != "false",
                "{lane}/{command}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let receipts: Vec<_> = fs::read_dir(repo.path().join("target/jankurai/proof-receipts"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert_eq!(receipts.len(), 1);
            let receipt: Value = serde_json::from_slice(&fs::read(&receipts[0]).unwrap()).unwrap();
            assert_eq!(receipt["command"], command);
            assert_eq!(receipt["lane"], lane);
            assert_eq!(receipt["exit_code"], if command == "false" { 1 } else { 0 });
            assert!(
                receipt.get("rules_covered").is_none(),
                "{lane}/{command}: {receipt}"
            );
            let evidence: Value = serde_json::from_slice(
                &fs::read(repo.path().join("target/jankurai/evidence-index.json")).unwrap(),
            )
            .unwrap();
            assert!(
                evidence.get("coverage_verdicts").is_none(),
                "{lane}/{command}: {evidence}"
            );
            assert_eq!(
                evidence["failed_receipts"].as_array().unwrap().len(),
                usize::from(command == "false")
            );
            if lane == "required" && command == "true" {
                imported_claims_fail_even_with_matching_digests(repo.path(), &receipts[0]);
            }
        }
    }
}

fn verify(repo: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_jankurai"))
        .current_dir(repo)
        .args([
            "proof-verify",
            ".",
            "--plan",
            "target/jankurai/proof-plan.json",
            "--evidence-index",
            "target/jankurai/evidence-index.json",
            "--out",
            "target/verification.json",
            "--md",
            "target/verification.md",
        ])
        .output()
        .unwrap()
}

fn imported_claims_fail_even_with_matching_digests(repo: &Path, receipt_path: &Path) {
    let original_receipt = fs::read(receipt_path).unwrap();
    let evidence_path = repo.join("target/jankurai/evidence-index.json");
    let original_evidence = fs::read(&evidence_path).unwrap();
    let positive = verify(repo);
    assert!(
        positive.status.success(),
        "{}",
        String::from_utf8_lossy(&positive.stderr)
    );
    let claims = json!([
        {"rule_id":"HLT-008-FALSE-GREEN-RISK", "status":"covered"},
        {"rule_id":"HLT-024-AGENT-TOOL-SUPPLY-GAP", "status":"covered"}
    ]);
    for (receipt_claim, index_claim) in [(true, false), (false, true), (true, true)] {
        let mut receipt: Value = serde_json::from_slice(&original_receipt).unwrap();
        let mut evidence: Value = serde_json::from_slice(&original_evidence).unwrap();
        if receipt_claim {
            receipt["rules_covered"] = claims.clone();
        }
        let receipt_bytes = serde_json::to_vec_pretty(&receipt).unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(&receipt_bytes));
        fs::write(receipt_path, receipt_bytes).unwrap();
        // An attacker can update every authored digest along with the receipt.
        for key in ["receipt_digests", "artifact_digests"] {
            for entry in evidence[key].as_array_mut().unwrap() {
                if repo.join(entry["path"].as_str().unwrap()) == receipt_path {
                    entry["sha256"] = json!(digest);
                }
            }
        }
        if index_claim {
            evidence["coverage_verdicts"] = claims.clone();
        }
        fs::write(
            &evidence_path,
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();
        let output = verify(repo);
        assert!(!output.status.success(), "imported coverage accepted");
        let report: Value =
            serde_json::from_slice(&fs::read(repo.join("target/verification.json")).unwrap())
                .unwrap();
        assert_eq!(report["verdict"], "blocked");
        assert!(report.get("coverage_verdicts").is_none());
        let issues = report["issues"].as_array().unwrap();
        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .all(|issue| issue.as_str().unwrap().contains("unverified rule coverage")),
            "{report}"
        );
    }
    fs::write(receipt_path, original_receipt).unwrap();
    fs::write(evidence_path, original_evidence).unwrap();
}
