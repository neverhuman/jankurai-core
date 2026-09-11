use crate::validation::{self, ArtifactSchema};
use anyhow::Result;
use jankurai_proofmark::{build_proofmark, ProofMarkMode, ProofMarkRequest};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ProofMarkRustArgs {
    pub repo: PathBuf,
    pub changed: Vec<PathBuf>,
    pub changed_from: Option<String>,
    pub mode: String,
    pub obligations: String,
    pub coverage: Option<PathBuf>,
    pub mutation: Option<PathBuf>,
    pub negative_proof: Vec<String>,
    pub out: String,
    pub proof_receipt: String,
    pub md: String,
}

pub fn run_rust(mut args: ProofMarkRustArgs) -> Result<()> {
    let mode = args.mode.parse::<ProofMarkMode>()?;
    if let Some(base) = args.changed_from.as_deref() {
        args.changed_from = Some(crate::audit::verified_git_comparison(&args.repo, base)?.0);
    }
    let mut output = build_proofmark(ProofMarkRequest {
        repo_root: args.repo.clone(),
        changed_paths: args.changed,
        changed_from: args.changed_from,
        obligations_path: Some(PathBuf::from(&args.obligations)),
        coverage_path: args.coverage,
        mutation_path: args.mutation,
        negative_proofs: args.negative_proof,
        mode,
    })?;
    // This command parses historical coverage and mutation files. It does not
    // observe their producers, so its output cannot grant execution coverage.
    output.proof_receipt.rules_covered.clear();
    if let Some(claims) = output.proof_receipt.extensions.remove("proofmark") {
        output
            .proof_receipt
            .extensions
            .insert("unverified_proofmark".into(), claims);
    }
    output.proof_receipt.extensions.insert(
        "trust_status".into(),
        serde_json::json!("unverified-import"),
    );
    if mode == ProofMarkMode::Required {
        output.proof_receipt.exit_code = 1;
    }
    output.markdown.insert_str(0, "> Imported coverage and mutation data: diagnostic only. No trusted execution or proof coverage is established.\n\n");
    ensure_parent(&args.out)?;
    ensure_parent(&args.proof_receipt)?;
    ensure_parent(&args.md)?;
    validation::write_json(
        &args.repo,
        ArtifactSchema::ProofMarkReceipt,
        &args.out,
        &output.receipt,
    )?;
    validation::write_json(
        &args.repo,
        ArtifactSchema::ProofReceipt,
        &args.proof_receipt,
        &output.proof_receipt,
    )?;
    crate::render::write_markdown(&args.md, &output.markdown)?;
    if mode == ProofMarkMode::Required {
        anyhow::bail!(
            "proofmark required mode needs trusted execution observations; imported reports cannot establish proof coverage"
        );
    }
    Ok(())
}

fn ensure_parent(path: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}
