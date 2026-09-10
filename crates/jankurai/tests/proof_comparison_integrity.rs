use std::{fs, path::Path, process::Command};

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn repository() -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "-q"]);
    git(repo.path(), &["config", "user.email", "test@example.com"]);
    git(repo.path(), &["config", "user.name", "Comparison test"]);
    fs::write(repo.path().join("README.md"), "# Input\n").unwrap();
    git(repo.path(), &["add", "README.md"]);
    git(repo.path(), &["commit", "-qm", "initial"]);
    repo
}

#[test]
fn failed_git_comparisons_cannot_publish_successful_proof_artifacts() {
    let repo = repository();
    for command in [
        vec!["proof"],
        vec!["proofbind", "verify"],
        vec!["proofmark", "rust"],
    ] {
        let out = repo.path().join("existing-proof.json");
        fs::write(&out, "preserve accepted evidence").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_jankurai"))
            .current_dir(repo.path())
            .args(command)
            .args([".", "--changed-from", "origin/absent", "--out"])
            .arg(&out)
            .output()
            .unwrap();
        assert!(!output.status.success(), "missing base was accepted");
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot resolve comparison base"));
        assert_eq!(
            fs::read_to_string(&out).unwrap(),
            "preserve accepted evidence"
        );
    }
}

#[test]
fn complete_git_comparisons_preserve_filenames_and_legitimate_empty_deltas() {
    let repo = repository();
    let base = git(repo.path(), &["rev-parse", "HEAD"]);
    assert!(jankurai::audit::changed_paths_from_git(repo.path(), &base)
        .unwrap()
        .is_empty());
    let path = repo.path().join(" source\nname.rs ");
    fs::write(&path, "pub fn example() {}\n").unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-qm", "source"]);
    assert_eq!(
        jankurai::audit::changed_paths_from_git(repo.path(), &base).unwrap(),
        vec![path]
    );
    // A valid but unrelated commit still cannot provide a three-dot comparison.
    git(repo.path(), &["checkout", "--orphan", "unrelated"]);
    git(repo.path(), &["commit", "-qm", "unrelated source"]);
    assert!(jankurai::audit::changed_paths_from_git(repo.path(), &base).is_err());
}

#[test]
fn ci_uses_real_pr_and_resulting_main_comparison_bases() {
    let repo = repository();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ops/ci/comparison-base.sh");
    let run = || {
        Command::new("/bin/bash")
            .current_dir(repo.path())
            .arg(&script)
            .output()
            .unwrap()
    };
    assert!(!run().status.success(), "missing origin/main was accepted");
    let base = git(repo.path(), &["rev-parse", "HEAD"]);
    git(
        repo.path(),
        &["update-ref", "refs/remotes/origin/main", &base],
    );
    fs::write(repo.path().join("README.md"), "# Changed\n").unwrap();
    git(repo.path(), &["commit", "-qam", "change"]);
    let pr = run();
    assert!(pr.status.success());
    assert_eq!(String::from_utf8(pr.stdout).unwrap().trim(), base);
    git(
        repo.path(),
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    let main = run();
    assert!(main.status.success());
    assert_eq!(String::from_utf8(main.stdout).unwrap().trim(), base);
}
