use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use jankurai::validation::{self, ArtifactSchema};
use tempfile::tempdir;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_jankurai"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn write_policy(repo: &std::path::Path) {
    fs::create_dir_all(repo.join("agent")).unwrap();
    fs::write(
        repo.join("agent/security-policy.toml"),
        r#"
schema_version = "1.0.0"
enabled_tools = ["gitleaks", "cargo audit"]
required_tools = ["gitleaks"]
advisory_tools = ["cargo audit"]

[severity_thresholds]
fail_lane_on = "high"
"#,
    )
    .unwrap();
}

#[test]
fn required_tool_failure_exits_nonzero_and_records_real_exit_code() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("tools")).unwrap();
    write_policy(repo.path());

    let bin_dir = tempdir().unwrap();
    let gitleaks = bin_dir.path().join("gitleaks");
    fs::write(
        &gitleaks,
        "#!/usr/bin/env bash\necho gitleaks-boom >&2\nexit 7\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&gitleaks).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&gitleaks, perms).unwrap();

    fs::write(
        repo.path().join("tools/security-lane.sh"),
        fs::read_to_string(repo_root().join("tools/security-lane.sh")).unwrap(),
    )
    .unwrap();

    let evidence_path = repo.path().join("out/evidence.json");
    let output = Command::new(binary_path())
        .current_dir(repo.path())
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.path().display(),
                env::var("PATH").unwrap_or_default()
            ),
        )
        .args([
            "security",
            "run",
            ".",
            "--script",
            "tools/security-lane.sh",
            "--out",
            evidence_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "security run unexpectedly succeeded"
    );

    let text = fs::read_to_string(&evidence_path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    validation::validate_value(repo.path(), ArtifactSchema::SecurityEvidence, &value).unwrap();
    assert_eq!(value["exit_code"], 7);
    assert_eq!(value["commands"][0]["tool"], "gitleaks");
    assert_eq!(value["commands"][0]["status"], "failed");
    assert_eq!(value["commands"][0]["exit_code"], 7);

    let log_rel = value["log_path"].as_str().unwrap();
    let log_text = fs::read_to_string(repo.path().join(log_rel)).unwrap();
    assert!(log_text.contains("gitleaks-boom"));
}

#[test]
fn ci_security_lane_scans_a_source_snapshot_without_mutating_workspace() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("tools")).unwrap();
    write_policy(repo.path());

    fs::write(
        repo.path().join("tools/security-lane.sh"),
        fs::read_to_string(repo_root().join("tools/security-lane.sh")).unwrap(),
    )
    .unwrap();

    let status = Command::new("git")
        .current_dir(repo.path())
        .args(["init"])
        .status()
        .unwrap();
    assert!(status.success());

    let status = Command::new("git")
        .current_dir(repo.path())
        .args(["config", "user.email", "ci@example.com"])
        .status()
        .unwrap();
    assert!(status.success());

    let status = Command::new("git")
        .current_dir(repo.path())
        .args(["config", "user.name", "CI"])
        .status()
        .unwrap();
    assert!(status.success());

    let status = Command::new("git")
        .current_dir(repo.path())
        .args(["add", "."])
        .status()
        .unwrap();
    assert!(status.success());

    let status = Command::new("git")
        .current_dir(repo.path())
        .args(["commit", "-m", "init"])
        .status()
        .unwrap();
    assert!(status.success());

    fs::write(
        repo.path().join("junk.txt"),
        "should be removed by git clean\n",
    )
    .unwrap();
    assert!(repo.path().join("junk.txt").exists());

    let bin_dir = tempdir().unwrap();
    let gitleaks = bin_dir.path().join("gitleaks");
    fs::write(&gitleaks, "#!/usr/bin/env bash\necho gitleaks-ok\nexit 0\n").unwrap();
    let mut perms = fs::metadata(&gitleaks).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&gitleaks, perms).unwrap();

    let evidence_path = repo.path().join("target/jankurai/security/evidence.json");
    let output = Command::new(binary_path())
        .current_dir(repo.path())
        .env("CI", "true")
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.path().display(),
                env::var("PATH").unwrap_or_default()
            ),
        )
        .args([
            "security",
            "run",
            ".",
            "--script",
            "tools/security-lane.sh",
            "--out",
            evidence_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "security run failed: stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        repo.path().join("junk.txt").exists(),
        "source snapshot scanning should not delete the live workspace"
    );
}

#[test]
fn scanner_failures_preserve_previous_sbom_and_retained_attempts() {
    let repo = tempdir().unwrap();
    for directory in ["tools", "bin", "target/jankurai/security"] {
        fs::create_dir_all(repo.path().join(directory)).unwrap();
    }
    fs::write(repo.path().join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(repo.path().join("Cargo.lock"), "fixture lock input\n").unwrap();
    fs::write(
        repo.path().join("tools/security-lane.sh"),
        fs::read(repo_root().join("tools/security-lane.sh")).unwrap(),
    )
    .unwrap();
    // Fake executables test failure propagation and file custody only.
    for (name, script) in [
        ("gitleaks", "exit 0\n"),
        ("cargo", "if [[ $1 == deny && ${FAIL_TOOL:-} == cargo-deny ]]; then exit 7; fi\n"),
        ("syft", "[[ ${FAIL_TOOL:-} != syft ]] || exit 7\n[[ ${FAIL_TOOL:-} != missing-sbom ]] || exit 0\noutput=${!#}\nprintf '{}' > \"${output#*=}\"\n"),
        ("grype", "printf called > grype-called\n[[ ${FAIL_TOOL:-} != grype ]] || exit 7\n"),
    ] {
        let path = repo.path().join("bin").join(name);
        fs::write(&path, format!("#!/bin/bash\n{script}")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let sbom = repo.path().join("target/jankurai/security/sbom.json");
    fs::write(&sbom, "accepted prior SBOM").unwrap();
    let run = |failure: &str| {
        Command::new("/bin/bash")
            .current_dir(repo.path())
            .arg("tools/security-lane.sh")
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", repo.path().join("bin").display()),
            )
            .env("FAIL_TOOL", failure)
            .output()
            .unwrap()
    };
    for failure in ["cargo-deny", "syft", "grype", "missing-sbom"] {
        let output = run(failure);
        assert!(!output.status.success(), "accepted {failure}");
        assert_eq!(fs::read_to_string(&sbom).unwrap(), "accepted prior SBOM");
    }
    let attempts = fs::read_dir(repo.path().join("target/jankurai/security"))
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .count();
    assert_eq!(attempts, 4, "failed scan evidence was discarded");
    assert!(run("").status.success());
    assert_eq!(fs::read_to_string(&sbom).unwrap(), "{}");
    fs::remove_file(&sbom).unwrap();
    let sentinel = repo.path().join("unknown-file");
    fs::write(&sentinel, "preserve me").unwrap();
    std::os::unix::fs::symlink(&sentinel, &sbom).unwrap();
    assert!(!run("").status.success());
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "preserve me");
    fs::remove_file(&sbom).unwrap();
    fs::hard_link(&sentinel, &sbom).unwrap();
    assert!(run("").status.success());
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "preserve me");
    assert_eq!(fs::read_to_string(&sbom).unwrap(), "{}");
}
