//! Shim: the diff-audit implementation moved to the `jankurai-fleet` crate (W5
//! split). Types/helpers re-export verbatim; the entry point `run` is a thin
//! wrapper that injects core's audit runner and proof-plan runner so the moved
//! crate never depends back on core. `crate::commands::diff_audit::X` paths keep
//! resolving unchanged.
pub use jankurai_fleet::diff_audit::*;

use crate::audit::{self, AuditOptions};
use crate::commands::proof::{self, ProofPlanArgs};
use crate::model::Report;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Entry point for `jankurai diff-audit`. Injects core's audit runner and the
/// best-effort proof-plan runner exactly as the pre-split implementation did.
pub fn run(args: jankurai_fleet::diff_audit::DiffAuditArgs) -> Result<()> {
    let audit = |repo: &Path, changed: &[PathBuf], changed_fast: bool| -> Result<Report> {
        audit::run_audit_with_options(
            repo,
            changed,
            AuditOptions {
                self_audit: false,
                proof_receipts: None,
                changed_fast,
            },
        )
    };
    let proof = |repo: PathBuf,
                 changed: Vec<PathBuf>,
                 changed_from: Option<String>,
                 out: Option<String>,
                 md: Option<String>|
     -> Result<()> {
        proof::run_proof(ProofPlanArgs {
            repo,
            changed,
            changed_from,
            out,
            md,
        })
    };
    jankurai_fleet::diff_audit::run(args, &audit, &proof)
}
