#![cfg(unix)]

use serde_json::{json, Value};
use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

fn document() -> Value {
    json!({
        "bomFormat":"CycloneDX", "specVersion":"1.6", "version":1,
        "serialNumber":"urn:uuid:455791ce-efc7-4e6c-b1f9-359e283c3d65",
        "metadata": {
            "timestamp":"SCAN_TIME",
            "tools":{"components":[{"type":"application","name":"syft","version":"1.40.0"}]}
        },
        "components":[{"type":"library","name":"fixture","version":"1.0.0",
            "licenses":[{"license":{"id":"MIT"}}]}]
    })
}

fn run(repo: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_jankurai"))
        .current_dir(repo)
        .args(["security", "run", ".", "--strict", "--profile", "ci"])
        .output()
        .unwrap()
}

#[test]
fn required_sbom_is_validated_even_when_the_wrapper_reports_success() {
    let repo = tempfile::tempdir().unwrap();
    for directory in ["agent", "tools", "target/jankurai/security"] {
        fs::create_dir_all(repo.path().join(directory)).unwrap();
    }
    fs::write(repo.path().join("agent/security-policy.toml"),
        "schema_version = '1.0.0'\n[profiles.ci]\nenabled_tools = ['syft']\nrequired_tools = ['syft']\n").unwrap();
    let script = "#!/bin/bash\nset -euo pipefail\nsed \"s/SCAN_TIME/$(date -u +%Y-%m-%dT%H:%M:%SZ)/g\" input.json > target/jankurai/security/sbom.json\nprintf '%s\\n' 'jankurai-security-step={\"label\":\"syft\",\"tool\":\"syft\",\"shell_command\":\"synthetic validator fixture\",\"status\":\"ran\",\"exit_code\":0,\"advisory\":false}'\n";
    fs::write(repo.path().join("tools/security-lane.sh"), script).unwrap();
    let input = repo.path().join("input.json");
    let valid = document();
    fs::write(&input, serde_json::to_vec(&valid).unwrap()).unwrap();
    let positive = run(repo.path());
    assert!(
        positive.status.success(),
        "{}",
        String::from_utf8_lossy(&positive.stderr)
    );
    // These reports exercise the validator only, not supervised tool execution.
    let mutations = [
        ("/bomFormat", json!("unknown")),
        ("/specVersion", json!("1.5")),
        ("/serialNumber", json!("not-a-uuid")),
        ("/metadata/timestamp", json!("2020-01-01T00:00:00Z")),
        ("/metadata/timestamp", json!("2999-01-01T00:00:00Z")),
        ("/metadata/tools/components/0/version", json!("0.0.0")),
        ("/components/0/type", json!("made-up")),
        (
            "/components/0/licenses/0/license/id",
            json!("Not-An-SPDX-Identifier"),
        ),
        ("/components", Value::Null),
    ];
    for (pointer, value) in mutations {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        fs::write(&input, serde_json::to_vec(&changed).unwrap()).unwrap();
        let output = run(repo.path());
        assert!(!output.status.success(), "accepted {pointer}");
        let evidence: Value = serde_json::from_slice(
            &fs::read(repo.path().join("target/jankurai/security/evidence.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(evidence["exit_code"], 1);
        assert!(evidence["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["label"] == "sbom-validation" && step["blocking"] == true));
    }
    let text = serde_json::to_string(&valid).unwrap().replacen(
        "\"bomFormat\":\"CycloneDX\"",
        "\"bomFormat\":\"unknown\",\"bomFormat\":\"CycloneDX\"",
        1,
    );
    fs::write(&input, text).unwrap();
    assert!(
        !run(repo.path()).status.success(),
        "accepted duplicate JSON key"
    );
    fs::write(&input, serde_json::to_vec(&document()).unwrap()).unwrap();
    let sbom = repo.path().join("target/jankurai/security/sbom.json");
    fs::remove_file(&sbom).unwrap();
    symlink(&input, &sbom).unwrap();
    assert!(!run(repo.path()).status.success(), "accepted symlink SBOM");
    fs::remove_file(&sbom).unwrap();
    fs::write(
        repo.path().join("tools/security-lane.sh"),
        script.replace("sed \"s/SCAN_TIME/$(date -u +%Y-%m-%dT%H:%M:%SZ)/g\" input.json > target/jankurai/security/sbom.json\n", ""),
    )
    .unwrap();
    assert!(!run(repo.path()).status.success(), "accepted missing SBOM");
    fs::write(&sbom, "").unwrap();
    assert!(!run(repo.path()).status.success(), "accepted empty SBOM");
    fs::write(&sbom, serde_json::to_vec(&document()).unwrap()).unwrap();
    fs::File::options()
        .write(true)
        .open(&sbom)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH)
        .unwrap();
    assert!(!run(repo.path()).status.success(), "accepted stale SBOM");
}
