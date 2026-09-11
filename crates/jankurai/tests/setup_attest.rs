use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_jankurai")
}

fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
}

fn tiny_pinned_source() -> (TempDir, String) {
    let source = tempfile::tempdir().unwrap();
    assert!(git(source.path(), &["init"]).status.success());
    fs::write(source.path().join("PIN"), "supervised-setup-source\n").unwrap();
    assert!(git(source.path(), &["add", "PIN"]).status.success());
    let commit = git(source.path(), &["commit", "-qm", "pin"]);
    assert!(
        commit.status.success(),
        "{}",
        String::from_utf8_lossy(&commit.stderr)
    );
    let sha = String::from_utf8(git(source.path(), &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(sha.len(), 40);
    (source, sha)
}

fn attested_repo(pin_sha: &str) -> TempDir {
    let repo = tempfile::tempdir().unwrap();
    fs::create_dir_all(repo.path().join("ops/ci")).unwrap();
    fs::write(
        repo.path().join("ops/ci/github-setup.sh"),
        format!(
            "#!/usr/bin/env bash\nset -euo pipefail\ngit clone --no-checkout https://github.com/neverhuman/jankurai-core.git dest\ngit checkout --detach {pin_sha}\n"
        ),
    )
    .unwrap();
    repo
}

fn observation_path(repo: &Path) -> PathBuf {
    repo.join("target/jankurai/supervised-observations/ops-ci-github-setup.json")
}

fn setup_attest(repo: &Path, source: &Path) -> std::process::Output {
    Command::new(binary())
        .args(["setup-attest"])
        .arg(repo)
        .arg("--source")
        .arg(source)
        .output()
        .unwrap()
}

fn proofbind_required(repo: &Path, receipts: &Path) -> std::process::Output {
    Command::new(binary())
        .current_dir(repo)
        .args([
            "proofbind",
            "verify",
            ".",
            "--mode",
            "required",
            "--changed",
            "ops/ci/github-setup.sh",
            "--proof-receipts",
        ])
        .arg(receipts)
        .output()
        .unwrap()
}

#[test]
fn supervised_setup_observation_satisfies_required_github_setup() {
    let (source, sha) = tiny_pinned_source();
    let repo = attested_repo(&sha);
    let output = setup_attest(repo.path(), source.path());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observation: Value =
        serde_json::from_slice(&fs::read(observation_path(repo.path())).unwrap()).unwrap();
    assert_eq!(observation["handler_id"], "jankurai.setup_attest.v1");
    assert_eq!(observation["path"], "ops/ci/github-setup.sh");
    assert_eq!(observation["pin_sha"], sha);
    assert_eq!(observation["exit_code"], 0);
    let expected = format!(
        "{:x}",
        Sha256::digest(
            format!("jankurai.setup_attest.v1\n{sha}\nops/ci/github-setup.sh").as_bytes()
        )
    );
    assert_eq!(observation["command_digest"], expected);

    let receipts = repo.path().join("target/jankurai/junk-receipts");
    fs::create_dir_all(&receipts).unwrap();
    fs::write(receipts.join("forged.json"), "{}\n").unwrap();
    // Junk receipts stay untrusted and are not passed into the library matcher.
    // An empty receipts directory is also accepted; a forged JSON file here is
    // ignored by the handler overlay because it is not a qualified observation.
    let empty = repo.path().join("target/jankurai/empty-receipts");
    fs::create_dir_all(&empty).unwrap();
    let output = proofbind_required(repo.path(), &empty);
    let obligations_path = repo
        .path()
        .join("target/jankurai/proofbind/obligations.json");
    assert!(
        output.status.success(),
        "status={} stderr={} stdout={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let obligations: Value = serde_json::from_slice(&fs::read(&obligations_path).unwrap()).unwrap();
    assert!(obligations["summary"]["missing"].as_u64().unwrap() == 0);
    assert_eq!(obligations["summary"]["verdict"], "pass");
    assert!(obligations["obligations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|obligation| {
            obligation["path"] == "ops/ci/github-setup.sh" && obligation["satisfied"] == true
        }));
}

#[test]
fn prove_echo_and_true_still_cannot_mint_rules_covered() {
    for command in ["echo verified", "true"] {
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
        fs::write(
            repo.path().join("agent/proof-lanes.toml"),
            format!(
                "[[lane]]\nname = \"required\"\ncommand = {command:?}\npurpose = 'exercise outcome'\nrules_covered = ['HLT-008-FALSE-GREEN-RISK']\n"
            ),
        )
        .unwrap();
        let output = Command::new(binary())
            .current_dir(repo.path())
            .args(["prove", ".", "--changed", "input.rs"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let receipts: Vec<_> = fs::read_dir(repo.path().join("target/jankurai/proof-receipts"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(receipts.len(), 1);
        let receipt: Value = serde_json::from_slice(&fs::read(&receipts[0]).unwrap()).unwrap();
        assert!(
            receipt.get("rules_covered").is_none(),
            "{command}: {receipt}"
        );
    }
}

#[test]
fn missing_github_setup_script_writes_no_observation() {
    let repo = tempfile::tempdir().unwrap();
    let source = tempfile::tempdir().unwrap();
    let output = setup_attest(repo.path(), source.path());
    assert!(!output.status.success());
    assert!(!observation_path(repo.path()).exists());
    assert!(!repo
        .path()
        .join("target/jankurai/supervised-observations")
        .exists());
}

#[test]
fn forged_observation_digest_does_not_satisfy_required_mode() {
    let repo = attested_repo("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let dir = repo.path().join("target/jankurai/supervised-observations");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("ops-ci-github-setup.json"),
        serde_json::to_vec_pretty(&json!({
            "handler_id": "jankurai.setup_attest.v1",
            "handler_digest": "deadbeef",
            "command_digest": "forged",
            "path": "ops/ci/github-setup.sh",
            "pin_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "exit_code": 0
        }))
        .unwrap(),
    )
    .unwrap();
    let empty = repo.path().join("target/jankurai/empty-receipts");
    fs::create_dir_all(&empty).unwrap();
    let output = proofbind_required(repo.path(), &empty);
    let obligations_path = repo
        .path()
        .join("target/jankurai/proofbind/obligations.json");
    assert!(
        !output.status.success(),
        "forged observation satisfied required mode: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        obligations_path.exists(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let obligations: Value = serde_json::from_slice(&fs::read(&obligations_path).unwrap()).unwrap();
    assert!(obligations["summary"]["missing"].as_u64().unwrap() > 0);
    assert!(obligations["obligations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|obligation| {
            obligation["path"] == "ops/ci/github-setup.sh" && obligation["satisfied"] == false
        }));
}
