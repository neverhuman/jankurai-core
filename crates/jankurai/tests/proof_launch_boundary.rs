#![cfg(unix)]

use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn proof_preserves_selected_tools_and_ignores_shell_startup_injection() {
    let repo = tempfile::tempdir().unwrap();
    for directory in [
        "agent",
        "docs",
        "selected",
        "replacement",
        "home",
        "target/jankurai",
    ] {
        fs::create_dir_all(repo.path().join(directory)).unwrap();
    }
    fs::write(repo.path().join("docs/input.md"), "# Input\n").unwrap();
    fs::write(
        repo.path().join("agent/owner-map.json"),
        r#"{"owners":{"docs/":"tests"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"tests":{"docs/":{"command":"selected-tool","purpose":"verify selected tool"}}}"#,
    )
    .unwrap();
    fs::write(repo.path().join("agent/proof-lanes.toml"), "[[lane]]\nname = \"fixture\"\ncommand = \"selected-tool\"\npurpose = \"exercise launcher boundary\"\n").unwrap();
    for (directory, body) in [
        ("selected", "printf selected > selected-result\n"),
        (
            "replacement",
            "printf replaced > replaced-result\nexit 23\n",
        ),
    ] {
        let path = repo.path().join(directory).join("selected-tool");
        fs::write(&path, format!("#!/bin/bash\n{body}")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    // A PATH-resolved Bash would run this instead of the trusted shell launcher.
    let impostor = repo.path().join("selected/bash");
    fs::write(
        &impostor,
        "#!/bin/sh\nprintf impostor > impostor-result\nexit 24\n",
    )
    .unwrap();
    fs::set_permissions(impostor, fs::Permissions::from_mode(0o755)).unwrap();
    let startup = repo.path().join("startup.sh");
    fs::write(&startup, "printf startup > startup-result\n").unwrap();
    fs::write(
        repo.path().join("home/.bash_profile"),
        format!(
            "export PATH='{}:/usr/bin:/bin'\nprintf profile > profile-result\n",
            repo.path().join("replacement").display()
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jankurai"))
        .current_dir(repo.path())
        .args(["prove", ".", "--changed", "docs/input.md"])
        .env("HOME", repo.path().join("home"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", repo.path().join("selected").display()),
        )
        .env("BASH_ENV", &startup)
        .env("ENV", &startup)
        .env(
            "BASH_FUNC_selected-tool%%",
            "() { printf forged > function-result; }",
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(repo.path().join("selected-result")).unwrap(),
        "selected"
    );
    for forbidden in [
        "replaced-result",
        "profile-result",
        "startup-result",
        "impostor-result",
        "function-result",
    ] {
        assert!(
            !repo.path().join(forbidden).exists(),
            "executed {forbidden}"
        );
    }
    let entries: Vec<_> = fs::read_dir(repo.path().join("target/jankurai/proof-receipts"))
        .unwrap()
        .collect();
    assert_eq!(entries.len(), 1);
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(entries[0].as_ref().unwrap().path()).unwrap()).unwrap();
    assert_eq!(receipt["exit_code"], json!(0));
    assert_eq!(receipt["command"], json!("selected-tool"));
    assert!(receipt["extensions"].get("supervised_execution").is_none());
}
