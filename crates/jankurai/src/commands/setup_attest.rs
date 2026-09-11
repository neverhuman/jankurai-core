use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const HANDLER_ID: &str = "jankurai.setup_attest.v1";
pub const COVERED_PATH: &str = "ops/ci/github-setup.sh";
const DEFAULT_SOURCE: &str = "https://github.com/neverhuman/jankurai-core.git";

#[derive(Debug, Serialize)]
struct Observation {
    handler_id: String,
    handler_digest: String,
    command_digest: String,
    path: String,
    pin_sha: String,
    exit_code: i32,
}

struct TempTree(PathBuf);

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn handler_digest(handler_id: &str) -> String {
    hex_digest(handler_id)
}

pub fn command_digest(handler_id: &str, pin_sha: &str, path: &str) -> String {
    hex_digest(&format!("{handler_id}\n{pin_sha}\n{path}"))
}

fn hex_digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

pub fn run(repo: &Path, source_override: Option<PathBuf>) -> Result<()> {
    let script = repo.join(COVERED_PATH);
    let text = fs::read_to_string(&script)
        .with_context(|| format!("supervised setup attestation requires {}", script.display()))?;
    let pin_sha = parse_pin_sha(&text)?;
    let source = match source_override {
        Some(path) => path,
        None => PathBuf::from(parse_source_url(&text)),
    };

    let tmp = temp_tree()?;
    let dest = tmp.0.join("core");
    let mut clone = git_command();
    clone
        .args(["clone", "--no-checkout"])
        .arg(&source)
        .arg(&dest);
    finish_git(clone, "clone pinned auditor source")?;
    let mut checkout = git_command();
    checkout
        .arg("-C")
        .arg(&dest)
        .args(["checkout", "--detach", &pin_sha]);
    finish_git(checkout, "checkout pinned SHA")?;
    let head = git_stdout(&dest, &["rev-parse", "HEAD"])?;
    if !head.eq_ignore_ascii_case(&pin_sha) {
        bail!("checked-out HEAD {head} does not match pin {pin_sha}");
    }

    if dest.join("crates/jankurai/Cargo.toml").is_file() {
        let status = Command::new("cargo")
            .arg("install")
            .arg("--path")
            .arg(dest.join("crates/jankurai"))
            .arg("--locked")
            .arg("--root")
            .arg(tmp.0.join("ci-tools"))
            .status()
            .context("launch cargo install of pinned auditor")?;
        if !status.success() {
            bail!("cargo install of pinned auditor failed with {status}");
        }
    }

    let observation = Observation {
        handler_id: HANDLER_ID.to_string(),
        handler_digest: handler_digest(HANDLER_ID),
        command_digest: command_digest(HANDLER_ID, &pin_sha, COVERED_PATH),
        path: COVERED_PATH.to_string(),
        pin_sha,
        exit_code: 0,
    };
    let out = repo.join("target/jankurai/supervised-observations/ops-ci-github-setup.json");
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(&out, serde_json::to_vec_pretty(&observation)?)
        .with_context(|| format!("write {}", out.display()))?;
    Ok(())
}

fn parse_pin_sha(text: &str) -> Result<String> {
    let re = Regex::new(r"checkout --detach\s+([0-9a-fA-F]{40})").expect("pin SHA regex");
    let pins: Vec<String> = re
        .captures_iter(text)
        .map(|caps| caps[1].to_ascii_lowercase())
        .collect();
    if pins.len() != 1 {
        bail!(
            "{COVERED_PATH} must pin exactly one `checkout --detach <40-hex>` SHA, found {}",
            pins.len()
        );
    }
    Ok(pins.into_iter().next().expect("exactly one pin"))
}

fn parse_source_url(text: &str) -> String {
    if text.contains(DEFAULT_SOURCE) {
        return DEFAULT_SOURCE.to_string();
    }
    let re = Regex::new(r"git clone --no-checkout\s+(\S+)").expect("clone URL regex");
    match re.captures(text) {
        Some(caps) => caps[1].to_string(),
        None => DEFAULT_SOURCE.to_string(),
    }
}

fn temp_tree() -> Result<TempTree> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock")?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "jankurai-setup-attest-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
    Ok(TempTree(path))
}

fn finish_git(mut command: Command, action: &str) -> Result<()> {
    let output = command.output().with_context(|| format!("git {action}"))?;
    if !output.status.success() {
        bail!(
            "git {action} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn git_stdout(repo: &Path, args: &[&str]) -> Result<String> {
    let output = git_command()
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| format!("git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_command() -> Command {
    let mut command = Command::new("git");
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}
