use jankurai::model::SCHEMA_VERSION;
use jankurai::versions::check_versions;
use std::fs;
use tempfile::tempdir;

#[test]
fn versions_bindings_validate() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("VERSION"),
        format!("{}\n", env!("CARGO_PKG_VERSION")),
    )
    .unwrap();
    fs::create_dir_all(dir.path().join("crates/jankurai")).unwrap();
    fs::write(
        dir.path().join("crates/jankurai/Cargo.toml"),
        format!(
            "[package]\nname = \"jankurai\"\nversion = \"{}\"\n",
            env!("CARGO_PKG_VERSION")
        ),
    )
    .unwrap();
    fs::create_dir_all(dir.path().join("agent")).unwrap();
    fs::write(
        dir.path().join("agent/standard-version.toml"),
        format!(
            r#"
standard = "jankurai"
standard_version = "0.9.0"
paper_edition = "2026.05-ed8"
auditor_version = "{ver}"
schema_version = "{schema}"
target_stack = "rust-ts-vite-react-postgres-bounded-python"

[[artifact]]
id = "paper-source"
path = "paper/jankurai.tex"
version_field = "paper_edition"
version = "2026.05-ed8"

[[artifact]]
id = "paper-render"
path = "paper/jankurai.pdf"
version_field = "paper_edition"
version = "2026.05-ed8"

[[artifact]]
id = "paper-agent-md"
path = "paper/jankurai.md"
version_field = "paper_edition"
version = "2026.05-ed8"

[[artifact]]
id = "coding-standard"
path = "docs/agent-native-standard.md"
version_field = "standard_version"
version = "0.9.0"

[[artifact]]
id = "agent-standard-brief"
path = "agent/JANKURAI_STANDARD.md"
version_field = "standard_version"
version = "0.9.0"

[[artifact]]
id = "ux-qa-runtime"
path = "packages/ux-qa"
version_field = "auditor_version"
version = "{ver}"
"#,
            ver = jankurai::model::AUDITOR_VERSION,
            schema = SCHEMA_VERSION,
        ),
    )
    .unwrap();
    fs::create_dir_all(dir.path().join("paper")).unwrap();
    fs::write(
        dir.path().join("paper/jankurai.md"),
        "Paper edition: `2026.05-ed8`\nStandard version: `0.9.0`\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("paper/jankurai.tex"),
        "\\input{paper/tex/frontmatter}\n",
    )
    .unwrap();
    fs::write(dir.path().join("paper/jankurai.pdf"), "").unwrap();
    fs::create_dir_all(dir.path().join("docs")).unwrap();
    fs::write(
        dir.path().join("docs/agent-native-standard.md"),
        "Standard version: `0.9.0`\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("agent/JANKURAI_STANDARD.md"),
        "Standard version: `0.9.0`\n",
    )
    .unwrap();
    fs::create_dir_all(dir.path().join("packages/ux-qa")).unwrap();
    fs::write(
        dir.path().join("packages/ux-qa/package.json"),
        format!(
            "{{\n  \"name\": \"@jankurai/ux-qa\",\n  \"version\": \"{}\"\n}}\n",
            jankurai::model::AUDITOR_VERSION
        ),
    )
    .unwrap();

    check_versions(dir.path()).unwrap();
    fs::write(
        dir.path().join("VERSION"),
        format!("prefix{}suffix", env!("CARGO_PKG_VERSION")),
    )
    .unwrap();
    assert!(check_versions(dir.path())
        .unwrap_err()
        .to_string()
        .contains("VERSION (auditor release)"));
}

#[test]
fn split_core_versions_validate_without_hub_owned_artifacts() {
    let dir = tempdir().unwrap();
    write_split_core(dir.path());
    check_versions(dir.path()).unwrap();
}

fn write_split_core(root: &std::path::Path) {
    fs::write(root.join("VERSION"), "1.7.0-split.0\n").unwrap();
    fs::create_dir_all(root.join("crates/jankurai")).unwrap();
    fs::write(
        root.join("crates/jankurai/Cargo.toml"),
        format!(
            "[package]\nname = \"jankurai\"\nversion = \"{}\"\n",
            env!("CARGO_PKG_VERSION")
        ),
    )
    .unwrap();
    fs::create_dir_all(root.join("agent")).unwrap();
    fs::write(
        root.join("agent/standard-version.toml"),
        format!(
            r#"
standard = "jankurai"
standard_version = "0.9.0"
paper_edition = "2026.05-ed8"
auditor_version = "{}"
schema_version = "{}"
target_stack = "rust-ts-vite-react-postgres-bounded-python"
split_family = "jankurai"
family_release = "1.7.0-split.0"
split_member = "jankurai-core"
split_release = "1.7.0-split.1"
"#,
            jankurai::model::AUDITOR_VERSION,
            SCHEMA_VERSION,
        ),
    )
    .unwrap();
    fs::write(
        root.join("agent/JANKURAI_STANDARD.md"),
        "Standard version: `0.9.0`\n",
    )
    .unwrap();

    fs::write(root.join("agent/split-member.toml"),
        "family = \"jankurai\"\nrepo = \"jankurai-core\"\nrelease_tag_pattern = \"jankurai-core-v1.7.0-split.1\"\n").unwrap();
}

#[test]
fn actual_checkout_version_declarations_are_consistent() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    check_versions(&root).unwrap();
}

#[test]
fn split_family_and_member_versions_are_checked_independently() {
    for (path, from, to, error) in [
        (
            "VERSION",
            "1.7.0-split.0",
            "1.7.0-split.1",
            "VERSION (family release)",
        ),
        (
            "VERSION",
            "1.7.0-split.0",
            "prefix1.7.0-split.0suffix",
            "VERSION (family release)",
        ),
        (
            "agent/standard-version.toml",
            "family_release = \"1.7.0-split.0\"",
            "family_release = \"2.0.0\"",
            "VERSION (family release)",
        ),
        (
            "agent/standard-version.toml",
            "split_release = \"1.7.0-split.1\"",
            "split_release = \"1.7.0-split.2\"",
            "release_tag_pattern",
        ),
        (
            "agent/split-member.toml",
            "jankurai-core-v1.7.0-split.1",
            "jankurai-core-v1.7.0-split.2",
            "release_tag_pattern",
        ),
    ] {
        let dir = tempdir().unwrap();
        write_split_core(dir.path());
        let file = dir.path().join(path);
        let original = fs::read_to_string(&file).unwrap();
        assert!(original.contains(from));
        fs::write(file, original.replace(from, to)).unwrap();
        assert!(check_versions(dir.path())
            .unwrap_err()
            .to_string()
            .contains(error));
    }
}

#[test]
fn split_identity_requires_complete_well_typed_declarations() {
    for key in [
        "split_family",
        "family_release",
        "split_member",
        "split_release",
    ] {
        for value in [
            None,
            Some(toml::Value::Integer(1)),
            Some(toml::Value::String(String::new())),
        ] {
            let dir = tempdir().unwrap();
            write_split_core(dir.path());
            let path = dir.path().join("agent/standard-version.toml");
            let mut manifest: toml::Value =
                toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            let fields = manifest.as_table_mut().unwrap();
            if let Some(value) = value {
                fields.insert(key.into(), value);
            } else {
                fields.remove(key);
            }
            fs::write(path, toml::to_string(&manifest).unwrap()).unwrap();
            assert!(
                check_versions(dir.path()).is_err(),
                "accepted invalid {key}"
            );
        }
    }
}

#[test]
fn split_identity_rejects_invalid_versions_and_wrong_member() {
    for (key, value) in [
        ("family_release", "invalid"),
        ("split_release", "invalid"),
        ("split_member", "another-core"),
        ("split_family", "another-family"),
    ] {
        let dir = tempdir().unwrap();
        write_split_core(dir.path());
        let path = dir.path().join("agent/standard-version.toml");
        let mut manifest: toml::Value =
            toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        manifest[key] = toml::Value::String(value.into());
        fs::write(path, toml::to_string(&manifest).unwrap()).unwrap();
        assert!(
            check_versions(dir.path()).is_err(),
            "accepted invalid {key}"
        );
    }
}

#[test]
fn executable_schema_and_member_bindings_reject_mismatches() {
    for (path, key, value) in [
        ("agent/standard-version.toml", "auditor_version", "0.0.0"),
        ("agent/standard-version.toml", "schema_version", "999.0.0"),
        ("agent/split-member.toml", "family", "another-family"),
        ("agent/split-member.toml", "repo", "another-core"),
    ] {
        let dir = tempdir().unwrap();
        write_split_core(dir.path());
        let file = dir.path().join(path);
        let mut manifest: toml::Value =
            toml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        manifest[key] = toml::Value::String(value.into());
        fs::write(file, toml::to_string(&manifest).unwrap()).unwrap();
        assert!(
            check_versions(dir.path()).is_err(),
            "accepted invalid {key}"
        );
    }
    let dir = tempdir().unwrap();
    write_split_core(dir.path());
    fs::remove_file(dir.path().join("agent/split-member.toml")).unwrap();
    assert!(check_versions(dir.path()).is_err());
}
