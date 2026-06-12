//! Shim: the fleet matrix implementation moved to the `jankurai-fleet` crate
//! (W5 split). Types/helpers re-export verbatim; the entry point `run` is a thin
//! wrapper that injects core's audit runner so the moved crate never depends
//! back on core. `crate::commands::fleet::X` paths keep resolving unchanged.
pub use jankurai_fleet::fleet::*;

use crate::audit::{run_audit_with_options, AuditOptions};
use crate::model::Report;
use anyhow::Result;
use std::path::Path;

/// Entry point for `jankurai fleet`. Injects the core audit runner exactly as the
/// pre-split implementation called `run_audit_with_options(repo, &[], default())`.
pub fn run(args: jankurai_fleet::fleet::FleetArgs) -> Result<()> {
    let audit = |repo: &Path| -> Result<Report> {
        run_audit_with_options(repo, &[], AuditOptions::default())
    };
    jankurai_fleet::fleet::run(args, &audit)
}
