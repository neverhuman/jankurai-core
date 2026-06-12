//! Shim: the repair-task bank implementation moved to the `jankurai-fleet` crate
//! (W5 split). Types/helpers re-export verbatim; the entry point `run` is a thin
//! wrapper that injects core's audit runner so the moved crate never depends
//! back on core. `crate::commands::repair_tasks::X` paths keep resolving unchanged.
pub use jankurai_fleet::repair_tasks::*;

use crate::audit::{run_audit_with_options, AuditOptions};
use crate::model::Report;
use anyhow::Result;
use std::path::Path;

/// Entry point for `jankurai repair-tasks`. Injects the core audit runner exactly
/// as the pre-split implementation called `run_audit_with_options(repo, &[], default())`.
pub fn run(args: jankurai_fleet::repair_tasks::RepairTasksArgs) -> Result<()> {
    let audit = |repo: &Path| -> Result<Report> {
        run_audit_with_options(repo, &[], AuditOptions::default())
    };
    jankurai_fleet::repair_tasks::run(args, &audit)
}
