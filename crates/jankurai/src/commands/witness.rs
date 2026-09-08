mod outcome;
mod receipts;

use crate::audit::{run_audit_with_options, AuditOptions};
use crate::commands::context_data::{push_unique, GeneratedZone, RepoCatalog};
use crate::commands::score::FindingSummary;
use crate::validation::{self, ArtifactSchema};
use anyhow::{Context, Result};
use receipts::{load_proof_receipts, load_proofbind_summary};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct WitnessArgs {
    pub repo: PathBuf,
    pub changed: Vec<PathBuf>,
    pub changed_from: Option<String>,
    pub baseline: Option<String>,
    pub proof_receipts: Option<String>,
    pub out: String,
    pub md: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MergeWitness {
    pub schema_version: String,
    pub standard_version: String,
    pub auditor_version: String,
    pub command: String,
    pub generated_at: String,
    pub repo: String,
    pub git: WitnessGit,
    pub changed_paths: Vec<String>,
    pub route_decisions: Vec<RouteDecision>,
    pub generated_zone_touches: Vec<GeneratedZoneTouch>,
    pub required_lanes: Vec<String>,
    pub available_proof_receipts: Vec<ProofReceiptSummary>,
    pub proofbind: ProofBindWitnessSummary,
    pub missing_evidence: Vec<String>,
    pub current_score: i32,
    pub current_raw_score: i32,
    pub baseline_score: Option<i32>,
    pub score_delta: Option<i32>,
    pub claimed_conformance_level: String,
    pub observed_conformance_level: String,
    pub conformance_decision: String,
    pub conformance_blockers: Vec<String>,
    pub caps_applied: Vec<String>,
    pub caps_added: Vec<String>,
    pub new_findings: Vec<FindingSummary>,
    pub resolved_findings: Vec<FindingSummary>,
    pub carried_findings: Vec<FindingSummary>,
    pub decision: String,
    pub next_repair: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WitnessGit {
    pub base_ref: Option<String>,
    pub base: Option<String>,
    pub head: Option<String>,
    pub dirty_worktree: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteDecision {
    pub path: String,
    pub owner: String,
    pub owner_route: String,
    pub test_command: String,
    pub proof_lane: String,
    pub decision: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedZoneTouch {
    pub path: String,
    pub zone: String,
    pub source: String,
    pub command: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofReceiptSummary {
    pub lane: String,
    pub command: String,
    pub exit_code: i32,
    pub receipt_path: Option<String>,
    pub git_head: Option<String>,
    pub changed_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProofBindWitnessSummary {
    pub changed_surface_count: usize,
    pub satisfied_obligation_count: usize,
    pub missing_obligation_count: usize,
    pub verdict: String,
}

pub fn run(args: WitnessArgs) -> Result<()> {
    let witness = build_witness(&args)?;
    validation::write_json(
        &args.repo,
        ArtifactSchema::MergeWitness,
        &args.out,
        &witness,
    )?;
    crate::render::write_markdown(&args.md, &render_markdown(&witness))?;
    if witness.decision != "pass" {
        anyhow::bail!("merge witness decision `{}`", witness.decision);
    }
    Ok(())
}

pub fn build_witness(args: &WitnessArgs) -> Result<MergeWitness> {
    let catalog = RepoCatalog::load(&args.repo)?;
    let changed = if let Some(base) = args.changed_from.as_deref() {
        changed_paths_from_git(&args.repo, base)?
    } else {
        args.changed.clone()
    };
    let changed_paths = normalize_paths(&args.repo, &changed);
    let report = run_audit_with_options(
        &args.repo,
        &[],
        AuditOptions {
            self_audit: false,
            proof_receipts: args.proof_receipts.clone(),
            changed_fast: false,
        },
    )?;
    let receipts = load_proof_receipts(&args.repo, args.proof_receipts.as_deref())?;
    let proofbind = load_proofbind_summary(&args.repo, args.proof_receipts.as_deref())?;
    let route_decisions = route_decisions(&catalog, &changed_paths);
    let required_lanes = required_lanes(&route_decisions);
    let available_lanes: BTreeSet<String> = receipts
        .iter()
        .map(|receipt| receipt.lane.clone())
        .collect();
    let mut missing_evidence = Vec::new();
    for lane in &required_lanes {
        if !available_lanes.contains(lane) {
            missing_evidence.push(format!(
                "required proof lane `{lane}` has no successful receipt"
            ));
        }
    }
    let generated_zone_touches = generated_zone_touches(&catalog.generated_zones, &changed_paths);
    if !generated_zone_touches.is_empty() {
        missing_evidence.push(
            "changed paths touch generated zones; source regeneration proof is required".into(),
        );
    }

    let baseline_path = args.baseline.as_ref().map(|path| args.repo.join(path));
    let assessment = outcome::assess(
        &report,
        baseline_path.as_deref(),
        &route_decisions,
        &proofbind,
        &mut missing_evidence,
    )?;
    let mut next_repair = Vec::new();
    for missing in assessment
        .conformance_blockers
        .iter()
        .chain(&assessment.review_reasons)
    {
        push_unique(&mut next_repair, missing.clone());
    }
    for finding in assessment.new_findings.iter().take(5) {
        push_unique(
            &mut next_repair,
            format!(
                "repair `{}` on `{}`: {}",
                finding.rule_id.as_deref().unwrap_or("unruled"),
                finding.path,
                finding.problem
            ),
        );
    }
    if next_repair.is_empty() {
        next_repair.push("merge proof is complete; keep receipts attached to the PR".into());
    }

    Ok(MergeWitness {
        schema_version: "1.0.0".into(),
        standard_version: crate::model::STANDARD_VERSION.into(),
        auditor_version: crate::model::AUDITOR_VERSION.into(),
        command: "jankurai witness".into(),
        generated_at: unix_seconds(),
        repo: args.repo.display().to_string(),
        git: WitnessGit {
            base_ref: args.changed_from.clone(),
            base: args
                .changed_from
                .as_deref()
                .and_then(|base| git_output(&args.repo, &["rev-parse", "--short", base])),
            head: git_output(&args.repo, &["rev-parse", "--short", "HEAD"]),
            dirty_worktree: git_dirty(&args.repo),
        },
        changed_paths,
        route_decisions,
        generated_zone_touches,
        required_lanes,
        available_proof_receipts: receipts,
        proofbind,
        missing_evidence,
        current_score: report.score,
        current_raw_score: report.raw_score,
        baseline_score: assessment.baseline_score,
        score_delta: assessment.score_delta,
        claimed_conformance_level: "HL3".into(),
        observed_conformance_level: assessment.observed_conformance_level,
        conformance_decision: assessment.decision.into(),
        conformance_blockers: assessment.conformance_blockers,
        caps_applied: report.caps_applied,
        caps_added: assessment.caps_added,
        new_findings: assessment.new_findings,
        resolved_findings: assessment.resolved_findings,
        carried_findings: assessment.carried_findings,
        decision: assessment.decision.into(),
        next_repair,
    })
}

pub fn git_dirty_for_receipt(repo: &Path) -> bool {
    git_dirty(repo)
}

fn route_decisions(catalog: &RepoCatalog, changed_paths: &[String]) -> Vec<RouteDecision> {
    changed_paths
        .iter()
        .map(|path| {
            let owner = catalog
                .owner_for_path(path)
                .unwrap_or("unmapped")
                .to_string();
            let owner_route = catalog
                .owner_prefix_for_path(path)
                .unwrap_or_else(|| "unmapped".into());
            let test = catalog.test_route_for_path(path);
            let test_command = test
                .as_ref()
                .map(|(_, spec)| spec.command.clone())
                .unwrap_or_else(|| "unmapped".into());
            let proof_lane = if test_command == "unmapped" {
                "unmapped".into()
            } else {
                catalog
                    .proof_lane_for_command(&test_command)
                    .unwrap_or_else(|| "test-map".into())
            };
            let (decision, reason) = if owner == "unmapped" {
                ("block", "path has no owner-map route")
            } else if test_command == "unmapped" {
                ("block", "path has no test-map proof route")
            } else {
                ("require-proof", "owner and proof route are mapped")
            };
            RouteDecision {
                path: path.clone(),
                owner,
                owner_route,
                test_command,
                proof_lane,
                decision: decision.into(),
                reason: reason.into(),
            }
        })
        .collect()
}

fn required_lanes(route_decisions: &[RouteDecision]) -> Vec<String> {
    let mut out = Vec::new();
    for decision in route_decisions {
        if decision.proof_lane != "unmapped" {
            push_unique(&mut out, decision.proof_lane.clone());
        }
    }
    out
}

fn generated_zone_touches(
    zones: &[GeneratedZone],
    changed_paths: &[String],
) -> Vec<GeneratedZoneTouch> {
    let mut out = Vec::new();
    for path in changed_paths {
        for zone in zones {
            let zone_path = zone.path.trim().trim_matches('/');
            if path == zone_path || path.starts_with(&format!("{zone_path}/")) {
                out.push(GeneratedZoneTouch {
                    path: path.clone(),
                    zone: zone.path.clone(),
                    source: zone.source.clone(),
                    command: zone.command.clone(),
                    read_only: zone.read_only,
                });
            }
        }
    }
    out
}

fn render_markdown(witness: &MergeWitness) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "# jankurai Merge Witness");
    let _ = writeln!(out);
    let _ = writeln!(out, "- decision: `{}`", witness.decision);
    let _ = writeln!(out, "- score: `{}`", witness.current_score);
    if let Some(delta) = witness.score_delta {
        let _ = writeln!(out, "- score delta: `{:+}`", delta);
    }
    let _ = writeln!(out, "- changed paths: `{}`", witness.changed_paths.len());
    let _ = writeln!(
        out,
        "- proofbind: surfaces=`{}` satisfied=`{}` missing=`{}` verdict=`{}`",
        witness.proofbind.changed_surface_count,
        witness.proofbind.satisfied_obligation_count,
        witness.proofbind.missing_obligation_count,
        witness.proofbind.verdict
    );
    let _ = writeln!(
        out,
        "- missing evidence: `{}`",
        witness.missing_evidence.len()
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Proof Matrix");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Lane | Status |");
    let _ = writeln!(out, "| --- | --- |");
    for lane in &witness.required_lanes {
        let status = if witness
            .available_proof_receipts
            .iter()
            .any(|receipt| &receipt.lane == lane)
        {
            "receipt"
        } else {
            "missing"
        };
        let _ = writeln!(out, "| `{}` | `{}` |", lane, status);
    }
    if witness.required_lanes.is_empty() {
        let _ = writeln!(out, "| `none` | `no changed proof routes` |");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Next Repair");
    for repair in &witness.next_repair {
        let _ = writeln!(out, "- {}", repair);
    }
    out
}

fn normalize_paths(repo: &Path, paths: &[PathBuf]) -> Vec<String> {
    let mut out = Vec::new();
    for path in paths {
        let candidate = if path.is_absolute() {
            path.clone()
        } else {
            repo.join(path)
        };
        let rel = candidate
            .strip_prefix(repo)
            .unwrap_or(&candidate)
            .to_string_lossy()
            .replace('\\', "/");
        push_unique(&mut out, rel);
    }
    out
}

fn changed_paths_from_git(repo: &Path, base: &str) -> Result<Vec<PathBuf>> {
    let commit = git_output(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{base}^{{commit}}"),
        ],
    )
    .context("cannot resolve witness base commit")?;
    let output = Command::new("git")
        .args([
            "diff",
            "--name-only",
            "-z",
            &format!("{commit}...HEAD"),
            "--",
        ])
        .current_dir(repo)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "cannot resolve witness changed paths: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let paths = String::from_utf8(output.stdout).context("witness changed paths are not UTF-8")?;
    Ok(paths
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(|path| repo.join(path))
        .collect())
}

fn git_output(repo: &Path, args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn git_dirty(repo: &Path) -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo)
        .output()
        .ok()
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(false)
}

fn unix_seconds() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}
