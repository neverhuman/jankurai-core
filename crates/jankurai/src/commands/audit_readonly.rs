//! Admission for CLI audits that keep repository and cache state unchanged.
use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

/// Configure metadata-only Git operations before dispatching a CLI audit.
///
/// # Safety
/// Call only during single-threaded startup, before any environment readers or
/// audit workers can run concurrently.
pub unsafe fn configure_git_reads() {
    let inherited = std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| key.to_string_lossy().starts_with("GIT_"))
        .collect::<Vec<_>>();
    for key in inherited {
        std::env::remove_var(key);
    }
    for (key, value) in [
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_CONFIG_COUNT", "2"),
        ("GIT_CONFIG_KEY_0", "core.fsmonitor"),
        ("GIT_CONFIG_VALUE_0", "false"),
        ("GIT_CONFIG_KEY_1", "core.untrackedCache"),
        ("GIT_CONFIG_VALUE_1", "false"),
    ] {
        std::env::set_var(key, value);
    }
}

pub fn validate_outputs<'a>(repo: &Path, outputs: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let repo = repo.canonicalize().context("resolve read-only source")?;
    let mut destinations = BTreeSet::new();
    let mut stdout = false;
    for output in outputs {
        if output == "-" {
            if stdout {
                bail!("read-only audit permits only one stdout report");
            }
            stdout = true;
            continue;
        }
        let path = Path::new(output);
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut normalized = PathBuf::new();
        for component in absolute.components() {
            match component {
                Component::CurDir => {}
                // Lexically removing `..` would disagree with the kernel when
                // an earlier component is a symlink into the source tree.
                Component::ParentDir => bail!("read-only report paths may not contain '..'"),
                other => normalized.push(other),
            }
        }
        match fs::symlink_metadata(&normalized) {
            Ok(_) => bail!(
                "read-only audit requires fresh report outputs: {}",
                normalized.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect read-only output"),
        }
        let mut ancestor = normalized.as_path();
        let mut missing = Vec::new();
        loop {
            match fs::symlink_metadata(ancestor) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(
                        ancestor
                            .file_name()
                            .context("invalid report output")?
                            .to_owned(),
                    );
                    ancestor = ancestor
                        .parent()
                        .context("report output has no existing parent")?;
                }
                Err(error) => return Err(error).context("inspect report parent"),
            }
        }
        let mut resolved = ancestor.canonicalize().context("resolve report parent")?;
        if !resolved.is_dir() {
            bail!("read-only report parent is not a directory");
        }
        for name in missing.iter().rev() {
            resolved.push(name);
        }
        if resolved.starts_with(&repo) {
            bail!(
                "read-only audit requires report outputs outside the repository: {}",
                normalized.display()
            );
        }
        if !destinations.insert(resolved) {
            bail!("read-only audit report outputs must be distinct");
        }
    }
    Ok(())
}

/// Publish a fresh report without truncating evidence created since admission.
pub fn write_report(repo: &Path, output: &str, content: &str) -> Result<()> {
    validate_outputs(repo, [output])?;
    if output == "-" {
        std::io::stdout().lock().write_all(content.as_bytes())?;
        return Ok(());
    }
    if crate::audit::fs::is_read_only_exception_path(output) {
        bail!("automated writes to docs/exceptions are blocked; edit the exception file manually");
    }
    let path = Path::new(output);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create fresh report {output}"))?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}
