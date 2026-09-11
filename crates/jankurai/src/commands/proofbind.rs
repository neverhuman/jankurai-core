use crate::validation::{self, ArtifactSchema};
use anyhow::Result;
use jankurai_proofbind::{build_proofbind, ProofBindMode, ProofBindObligations, ProofBindRequest};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

use super::setup_attest::COVERED_PATH;

#[derive(Debug, Clone)]
pub struct ProofBindMapArgs {
    pub repo: PathBuf,
    pub changed: Vec<PathBuf>,
    pub changed_from: Option<String>,
    pub mode: String,
    pub proof_receipts: String,
    pub out: String,
    pub obligations_out: String,
    pub md: String,
}

#[derive(Debug, Clone)]
pub struct ProofBindVerifyArgs {
    pub repo: PathBuf,
    pub changed: Vec<PathBuf>,
    pub changed_from: Option<String>,
    pub mode: String,
    pub proof_receipts: String,
    pub out: String,
    pub obligations_out: String,
    pub md: String,
}

pub fn run_map(args: ProofBindMapArgs) -> Result<()> {
    write_outputs(args)
}

pub fn run_verify(args: ProofBindVerifyArgs) -> Result<()> {
    write_outputs(ProofBindMapArgs {
        repo: args.repo,
        changed: args.changed,
        changed_from: args.changed_from,
        mode: args.mode,
        proof_receipts: args.proof_receipts,
        out: args.out,
        obligations_out: args.obligations_out,
        md: args.md,
    })
}

fn write_outputs(mut args: ProofBindMapArgs) -> Result<()> {
    let mode = args.mode.parse::<ProofBindMode>()?;
    if let Some(base) = args.changed_from.as_deref() {
        args.changed_from = Some(crate::audit::verified_git_comparison(&args.repo, base)?.0);
    }
    let imports = super::witness::load_proof_receipts(&args.repo, Some(&args.proof_receipts))?;
    let mut output = build_proofbind(ProofBindRequest {
        repo_root: args.repo.clone(),
        changed_paths: args.changed,
        changed_from: args.changed_from,
        mode,
        // The pinned legacy library does not distinguish imported claims from
        // execution authority. Never pass file claims into its matcher.
        proof_receipts: None,
    })?;
    apply_supervised_observations(&args.repo, mode, &mut output.obligations);
    output.markdown =
        jankurai_proofbind::summary::render_markdown(&output.witness, &output.obligations);
    if !imports.is_empty() {
        output.markdown.push_str(&format!(
            "\nImported receipts: {} (unverified; diagnostic only, no proof coverage).\n",
            imports.len()
        ));
    }
    ensure_parent(&args.out)?;
    ensure_parent(&args.obligations_out)?;
    ensure_parent(&args.md)?;
    write_witness(&args.repo, &args.out, &output.witness)?;
    validation::write_json(
        &args.repo,
        ArtifactSchema::ProofBindObligations,
        &args.obligations_out,
        &output.obligations,
    )?;
    crate::render::write_markdown(&args.md, &output.markdown)?;
    if mode == ProofBindMode::Required && output.obligations.summary.missing > 0 {
        anyhow::bail!(
            "proofbind required mode has {} missing obligation(s)",
            output.obligations.summary.missing
        );
    }
    Ok(())
}

fn apply_supervised_observations(
    repo: &Path,
    mode: ProofBindMode,
    obligations: &mut ProofBindObligations,
) {
    let needs_setup = obligations
        .obligations
        .iter()
        .any(|obligation| covers_github_setup(&obligation.path));
    if !needs_setup {
        return;
    }
    // Trust only a handler that succeeds in this process. Disk JSON is an
    // artifact, not an authority — a forged observation cannot mint coverage.
    let source = std::env::var_os("JANKURAI_SETUP_ATTEST_SOURCE").map(PathBuf::from);
    if super::setup_attest::run(repo, source).is_err() {
        return;
    }
    for obligation in &mut obligations.obligations {
        if covers_github_setup(&obligation.path) {
            obligation.satisfied = true;
            obligation.status = "satisfied".into();
        }
    }
    obligations.summary.satisfied = obligations
        .obligations
        .iter()
        .filter(|obligation| obligation.satisfied)
        .count();
    obligations.summary.missing = obligations
        .obligations
        .len()
        .saturating_sub(obligations.summary.satisfied);
    obligations.summary.high_or_critical_missing = obligations
        .obligations
        .iter()
        .filter(|obligation| {
            !obligation.satisfied && matches!(obligation.severity.as_str(), "high" | "critical")
        })
        .count();
    obligations.summary.verdict = obligation_verdict(
        mode,
        obligations.summary.missing,
        obligations.summary.high_or_critical_missing,
    )
    .into();
}

fn covers_github_setup(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized == COVERED_PATH || normalized.ends_with(COVERED_PATH)
}

fn obligation_verdict(
    mode: ProofBindMode,
    missing: usize,
    high_or_critical_missing: usize,
) -> &'static str {
    if missing == 0 {
        "pass"
    } else if mode == ProofBindMode::Required && high_or_critical_missing > 0 {
        "block"
    } else {
        "review"
    }
}

fn write_witness<T: serde::Serialize>(repo: &Path, path: &str, witness: &T) -> Result<()> {
    match validation::validate_serializable(repo, ArtifactSchema::ProofBindWitness, witness) {
        Ok(()) => validation::write_json(repo, ArtifactSchema::ProofBindWitness, path, witness),
        Err(error) => {
            let value = serde_json::to_value(witness)?;
            if witness_matches_core_surface_enum(&value) {
                crate::render::write_json(path, &serde_json::to_string_pretty(&value)?)
            } else {
                Err(error)
            }
        }
    }
}

fn witness_matches_core_surface_enum(value: &Value) -> bool {
    let Some(surfaces) = value.get("surfaces").and_then(Value::as_array) else {
        return false;
    };
    surfaces.iter().all(|surface| {
        surface
            .get("surface_type")
            .and_then(Value::as_str)
            .is_some_and(allowed_core_surface_type)
    })
}

fn allowed_core_surface_type(surface_type: &str) -> bool {
    matches!(
        surface_type,
        "rust_public_api"
            | "test_execution"
            | "authz_boundary"
            | "input_boundary"
            | "sql_query"
            | "db_migration"
            | "cli_command"
            | "mcp_tool"
            | "unsafe_or_process_sink"
            | "ci_hardening"
            | "business_invariant"
    )
}

fn ensure_parent(path: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}
