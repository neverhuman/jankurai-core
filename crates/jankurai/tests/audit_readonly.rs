use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn fixture() -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir(root.join("agent")).unwrap();
    fs::write(root.join("README.md"), "# Read-only audit fixture\n").unwrap();
    fs::write(root.join("AGENTS.md"), "Read agent/JANKURAI_STANDARD.md.\n").unwrap();
    fs::write(
        root.join("agent/JANKURAI_STANDARD.md"),
        "Standard version: `0.9.0`\n",
    )
    .unwrap();
    fs::write(
        root.join("agent/audit-policy.toml"),
        "minimum_score = 100\n",
    )
    .unwrap();
    // Read-only mode must not invoke an automatic badge publisher even when
    // the configured output is deliberately unusable.
    fs::write(
        root.join("agent/badge.toml"),
        "svg = 'README.md/invalid.svg'\n",
    )
    .unwrap();
    for args in [
        vec!["init", "-q"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
    ] {
        let result = Command::new("git")
            // Git 2.55 detaches automatic maintenance even for a fresh commit.
            // Finish the fixture's writer before taking the complete inventory;
            // otherwise its maintenance.lock can disappear during the audit.
            .args([
                "-c",
                "maintenance.autoDetach=false",
                "-c",
                "gc.autoDetach=false",
            ])
            .args(args)
            .current_dir(root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    directory
}

fn inventory(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    walkdir::WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .map(|entry| {
            let entry = entry.unwrap();
            let bytes = if entry.file_type().is_file() {
                fs::read(entry.path()).unwrap()
            } else {
                Vec::new()
            };
            (
                entry.path().strip_prefix(root).unwrap().to_path_buf(),
                bytes,
            )
        })
        .collect()
}

fn assert_inventory_unchanged(root: &Path, before: &BTreeMap<PathBuf, Vec<u8>>) {
    let after = inventory(root);
    let paths = before.keys().chain(after.keys()).collect::<BTreeSet<_>>();
    let digest = |bytes: Option<&Vec<u8>>| {
        bytes.map_or_else(
            || "absent".into(),
            |bytes| format!("{:x}", Sha256::digest(bytes)),
        )
    };
    let changes = paths
        .into_iter()
        .filter_map(|path| {
            let old = before.get(path);
            let new = after.get(path);
            (old != new).then(|| format!("{}: {} -> {}", path.display(), digest(old), digest(new)))
        })
        .collect::<Vec<_>>();
    assert!(
        changes.is_empty(),
        "audit changed source/Git inventory:\n{}",
        changes.join("\n")
    );
}

fn audit(repo: &Path, json: &Path, markdown: &Path, mode: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_jankurai"))
        .arg("audit")
        .arg(repo)
        .args(["--read-only", "--full", "--mode", mode])
        .arg("--json")
        .arg(json)
        .arg("--md")
        .arg(markdown)
        .args(extra)
        .env_remove("JANKURAI_NO_UPDATE_CHECK")
        .env("JANKURAI_TEST_LATEST_VERSION", "9.9.9")
        .output()
        .unwrap()
}

#[test]
fn complete_audits_preserve_source_git_state_and_all_automatic_outputs() {
    let repo = fixture();
    let before = inventory(repo.path());
    for mode in ["advisory", "standard"] {
        let output = tempfile::tempdir().unwrap();
        let json = output.path().join("report.json");
        let markdown = output.path().join("report.md");
        let result = audit(repo.path(), &json, &markdown, mode, &[]);
        assert_eq!(
            result.status.success(),
            mode == "advisory",
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: Value = serde_json::from_slice(&fs::read(json).unwrap()).unwrap();
        assert_eq!(report["decision"]["passed"], false);
        assert_eq!(report["decision"]["minimum_score"], 100);
        assert!(fs::metadata(markdown).unwrap().len() > 0);
        assert_inventory_unchanged(repo.path(), &before);
    }
}

#[test]
fn source_outputs_aliases_and_existing_evidence_are_refused_before_any_write() {
    let repo = fixture();
    let output = tempfile::tempdir().unwrap();
    let before = inventory(repo.path());
    let fresh = output.path().join("report.md");
    for json in [
        repo.path().join("new-report.json"),
        repo.path().join("target/new/report.json"),
        repo.path().join("README.md"),
    ] {
        let result = audit(repo.path(), &json, &fresh, "advisory", &[]);
        assert!(!result.status.success());
        assert!(!fresh.exists());
        assert_inventory_unchanged(repo.path(), &before);
    }
    let same = output.path().join("same");
    assert!(jankurai::commands::audit_readonly::validate_outputs(repo.path(), ["-", "-"]).is_err());
    assert!(!audit(repo.path(), &same, &same, "advisory", &[])
        .status
        .success());
    assert!(!same.exists());
    fs::write(&same, "prior accepted evidence").unwrap();
    assert!(!audit(repo.path(), &same, &fresh, "advisory", &[])
        .status
        .success());
    assert_eq!(
        fs::read_to_string(&same).unwrap(),
        "prior accepted evidence"
    );
    assert!(!fresh.exists());
    let concurrent = output.path().join("concurrent.json");
    let concurrent_name = concurrent.to_str().unwrap();
    jankurai::commands::audit_readonly::validate_outputs(repo.path(), [concurrent_name]).unwrap();
    fs::write(&concurrent, "another publisher's evidence").unwrap();
    assert!(jankurai::commands::audit_readonly::write_report(
        repo.path(),
        concurrent_name,
        "replacement"
    )
    .is_err());
    assert_eq!(
        fs::read_to_string(concurrent).unwrap(),
        "another publisher's evidence"
    );
}

#[cfg(unix)]
#[test]
fn redirected_outputs_and_repository_fsmonitor_cannot_write_source_or_execute() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let repo = fixture();
    let output = tempfile::tempdir().unwrap();
    symlink(repo.path(), output.path().join("redirected")).unwrap();
    let result = audit(
        repo.path(),
        &output.path().join("redirected/report.json"),
        &output.path().join("report.md"),
        "advisory",
        &[],
    );
    assert!(!result.status.success());
    assert!(!repo.path().join("report.json").exists());
    symlink(
        repo.path().join("agent"),
        output.path().join("nested-source"),
    )
    .unwrap();
    let result = audit(
        repo.path(),
        &output.path().join("nested-source/../escaped.json"),
        &output.path().join("report.md"),
        "advisory",
        &[],
    );
    assert!(!result.status.success());
    assert!(!repo.path().join("escaped.json").exists());
    let hook = output.path().join("fsmonitor");
    let sentinel = output.path().join("executed");
    fs::write(
        &hook,
        format!("#!/bin/sh\nprintf invoked > '{}'\n", sentinel.display()),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Command::new("git")
        .arg("config")
        .arg("core.fsmonitor")
        .arg(&hook)
        .current_dir(repo.path())
        .status()
        .unwrap()
        .success());
    let before = inventory(repo.path());
    let result = audit(
        repo.path(),
        &output.path().join("report.json"),
        &output.path().join("report.md"),
        "advisory",
        &[],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!sentinel.exists());
    assert_inventory_unchanged(repo.path(), &before);
    let ordinary = Command::new(env!("CARGO_BIN_EXE_jankurai"))
        .arg("audit")
        .arg(repo.path())
        .args([
            "--full",
            "--mode",
            "advisory",
            "--no-badge",
            "--no-score-history",
        ])
        .arg("--json")
        .arg(output.path().join("ordinary.json"))
        .arg("--md")
        .arg(output.path().join("ordinary.md"))
        .env("JANKURAI_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    assert!(
        ordinary.status.success(),
        "{}",
        String::from_utf8_lossy(&ordinary.stderr)
    );
    assert!(
        !sentinel.exists(),
        "ordinary audit executed repository fsmonitor"
    );
}

#[test]
fn configured_output_errors_propagate_for_policy_failure_and_advisory_audits() {
    for failed_output in ["badge", "cache"] {
        let repo = fixture();
        let output = tempfile::tempdir().unwrap();
        fs::write(
            repo.path().join("agent/badge.toml"),
            "score = 'missing-badge-report.json'\n",
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_jankurai"));
        command
            .arg("audit")
            .arg(repo.path())
            .args([
                "--full",
                "--mode",
                if failed_output == "cache" {
                    "advisory"
                } else {
                    "standard"
                },
                "--no-score-history",
            ])
            .arg("--json")
            .arg(output.path().join("report.json"))
            .arg("--md")
            .arg(output.path().join("report.md"))
            .env("JANKURAI_NO_UPDATE_CHECK", "1");
        if failed_output == "cache" {
            command.arg("--no-badge");
            fs::write(repo.path().join("target"), "preserved user sentinel").unwrap();
        }
        let result = command.output().unwrap();
        let report: Value =
            serde_json::from_slice(&fs::read(output.path().join("report.json")).unwrap()).unwrap();
        // The fixture's conformance blockers stay active. Advisory normally
        // exits successfully; standard mode must expose the output failure
        // itself instead of warning and proceeding to policy enforcement.
        assert_eq!(report["decision"]["passed"], false);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let correct_failure = !result.status.success()
            && stderr.contains("Error:")
            && !stderr.contains("audit decision failed");
        if !correct_failure {
            fs::write(output.path().join("stderr.log"), &result.stderr).unwrap();
            let evidence = output.keep();
            let source = repo.keep();
            panic!("{failed_output} error was not propagated; evidence={evidence:?}, source={source:?}, stderr={stderr}");
        }
        if failed_output == "badge" {
            assert!(String::from_utf8_lossy(&result.stderr).contains("missing-badge-report.json"));
        } else {
            assert_eq!(
                fs::read_to_string(repo.path().join("target")).unwrap(),
                "preserved user sentinel"
            );
        }
    }
}
