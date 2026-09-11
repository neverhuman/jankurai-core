use crate::audit::{run_audit_with_options, AuditOptions};
use crate::commands::context_data::{push_unique, GeneratedZone, RepoCatalog};
use crate::commands::score::{finding_summary, FindingSummary};
use crate::model::{Finding, ProofReceipt, Report};
use crate::validation::{self, ArtifactSchema};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
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
    #[serde(default = "unverified_import")]
    pub trust_status: String,
}

fn unverified_import() -> String {
    "unverified-import".into()
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
    if matches!(
        witness.decision.as_str(),
        "block" | "ratchet_fail" | "release_fail"
    ) {
        anyhow::bail!("merge witness decision `{}`", witness.decision);
    }
    Ok(())
}

pub fn build_witness(args: &WitnessArgs) -> Result<MergeWitness> {
    let catalog = RepoCatalog::load(&args.repo)?;
    let changed = if let Some(base) = args.changed_from.as_deref() {
        crate::audit::changed_paths_from_git(&args.repo, base)?
    } else {
        args.changed.clone()
    };
    let changed_paths = normalize_paths(&args.repo, &changed);
    let report = run_audit_with_options(
        &args.repo,
        &changed,
        AuditOptions {
            self_audit: false,
            proof_receipts: args.proof_receipts.clone(),
            changed_fast: false,
        },
    )?;
    let receipts = load_proof_receipts(&args.repo, args.proof_receipts.as_deref())?;
    let proofbind = current_proofbind_summary(&args.repo, &changed)?;
    let route_decisions = route_decisions(&catalog, &changed_paths);
    let required_lanes = required_lanes(&route_decisions);
    // File-loaded receipts cannot mint rule coverage, but an exit-0 receipt
    // still records that the named lane ran. Witness must not block every
    // required lane merely because the public supervised executor is absent.
    let available_lanes: BTreeSet<String> = receipts
        .iter()
        .filter(|receipt| receipt.exit_code == 0)
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
    if proofbind.missing_obligation_count > 0 {
        missing_evidence.push(format!(
            "{} current semantic proof obligation(s) lack trusted execution evidence",
            proofbind.missing_obligation_count
        ));
    }
    let generated_zone_touches = generated_zone_touches(&catalog.generated_zones, &changed_paths);
    if !generated_zone_touches.is_empty() {
        missing_evidence.push(
            "changed paths touch generated zones; source regeneration proof is required".into(),
        );
    }

    let current_findings = finding_map_from_report(&report);
    let baseline_value = if let Some(path) = args.baseline.as_deref() {
        Some(load_json(&resolve(&args.repo, path))?)
    } else {
        None
    };
    let ratchet = baseline_value
        .as_ref()
        .map(|value| crate::audit::baseline::compare_report_to_value(&report, value))
        .transpose()?;
    let baseline_score = ratchet.as_ref().map(|comparison| comparison.baseline_score);
    let baseline_caps = baseline_value
        .as_ref()
        .map(|value| string_set(value.get("caps_applied")))
        .unwrap_or_default();
    let current_caps: BTreeSet<String> = report.caps_applied.iter().cloned().collect();
    let caps_added: Vec<String> = current_caps.difference(&baseline_caps).cloned().collect();
    let baseline_findings = baseline_value
        .as_ref()
        .map(finding_map_from_value)
        .unwrap_or_default();
    let (new_findings, resolved_findings, carried_findings) =
        finding_changes(&baseline_findings, &current_findings);
    let has_new_high = new_findings
        .iter()
        .any(|finding| matches!(finding.severity.as_str(), "high" | "critical"));
    let current_failed = report
        .decision
        .as_ref()
        .map(|decision| !decision.passed)
        .unwrap_or(false);
    let score_delta = baseline_score.map(|score| report.score - score);
    let decision = if ratchet
        .as_ref()
        .is_some_and(|comparison| !comparison.passed)
    {
        "ratchet_fail"
    } else if current_failed || has_new_high || !missing_evidence.is_empty() {
        "block"
    } else if baseline_score.is_none() || !new_findings.is_empty() || !caps_added.is_empty() {
        "review"
    } else {
        "pass"
    };
    let mut next_repair = Vec::new();
    for missing in &missing_evidence {
        push_unique(&mut next_repair, missing.clone());
    }
    for finding in new_findings.iter().take(5) {
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
    if proofbind.missing_obligation_count > 0 {
        push_unique(
            &mut next_repair,
            format!(
                "proofbind reports {} semantic proof obligation(s) still missing receipt evidence",
                proofbind.missing_obligation_count
            ),
        );
    }
    if next_repair.is_empty() {
        next_repair.push("merge proof is complete; keep receipts attached to the PR".into());
    }

    let conformance_blockers = missing_evidence.clone();
    let observed_conformance_level = if decision == "pass" { "HL3" } else { "HL2" };
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
        baseline_score,
        score_delta,
        claimed_conformance_level: "HL3".into(),
        observed_conformance_level: observed_conformance_level.into(),
        conformance_decision: decision.into(),
        conformance_blockers,
        caps_applied: report.caps_applied,
        caps_added,
        new_findings,
        resolved_findings,
        carried_findings,
        decision: decision.into(),
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

pub(super) fn load_proof_receipts(
    repo: &Path,
    path: Option<&str>,
) -> Result<Vec<ProofReceiptSummary>> {
    let Some(path) = path else {
        return Ok(vec![]);
    };
    let optional_default = path == "target/jankurai/proof-receipts";
    let path = resolve(repo, path);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && optional_default => {
            return Ok(vec![])
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect requested proof receipts {}", path.display()))
        }
    };
    if metadata.is_symlink() {
        anyhow::bail!(
            "proof receipt input may not be a symlink: {}",
            path.display()
        );
    }
    let mut entries = Vec::new();
    if metadata.is_dir() {
        for (index, entry) in fs::read_dir(&path)
            .with_context(|| format!("read {}", path.display()))?
            .enumerate()
        {
            if index >= 4096 {
                anyhow::bail!("proof receipt directory exceeds its entry limit");
            }
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
                entries.push(entry.path());
            }
        }
        entries.sort();
    } else {
        entries.push(path);
    }
    let mut out = Vec::new();
    for entry in entries {
        let value = load_json(&entry)?;
        validation::validate_value(repo, ArtifactSchema::ProofReceipt, &value)?;
        let receipt: ProofReceipt = serde_json::from_value(value)?;
        out.push(ProofReceiptSummary {
            lane: receipt.lane,
            command: receipt.command,
            exit_code: receipt.exit_code,
            receipt_path: Some(
                entry
                    .strip_prefix(repo)
                    .unwrap_or(&entry)
                    .to_string_lossy()
                    .replace('\\', "/"),
            ),
            git_head: receipt.git_head,
            changed_paths: receipt.changed_paths,
            trust_status: unverified_import(),
        });
    }
    Ok(out)
}

fn current_proofbind_summary(repo: &Path, changed: &[PathBuf]) -> Result<ProofBindWitnessSummary> {
    // Reclassify the current source. An authored obligations.json, including
    // an empty inventory or satisfied=true, cannot grant or remove coverage.
    let output = jankurai_proofbind::build_proofbind(jankurai_proofbind::ProofBindRequest {
        repo_root: repo.to_path_buf(),
        changed_paths: changed.to_vec(),
        changed_from: None,
        mode: jankurai_proofbind::ProofBindMode::Required,
        proof_receipts: None,
    })?;
    Ok(ProofBindWitnessSummary {
        changed_surface_count: output.witness.surfaces.len(),
        satisfied_obligation_count: output.obligations.summary.satisfied,
        missing_obligation_count: output.obligations.summary.missing,
        verdict: output.obligations.summary.verdict,
    })
}

fn finding_map_from_report(report: &Report) -> BTreeMap<String, FindingSummary> {
    let mut out = BTreeMap::new();
    for finding in &report.findings {
        let summary = finding_summary_from_model(finding);
        out.insert(summary.key.clone(), summary);
    }
    out
}

fn finding_summary_from_model(finding: &Finding) -> FindingSummary {
    let value = serde_json::to_value(finding).unwrap_or(Value::Null);
    finding_summary(&value)
}

fn finding_map_from_value(report: &Value) -> BTreeMap<String, FindingSummary> {
    let mut out = BTreeMap::new();
    let Some(findings) = report.get("findings").and_then(Value::as_array) else {
        return out;
    };
    for finding in findings {
        let summary = finding_summary(finding);
        out.insert(summary.key.clone(), summary);
    }
    out
}

fn finding_changes(
    baseline: &BTreeMap<String, FindingSummary>,
    current: &BTreeMap<String, FindingSummary>,
) -> (
    Vec<FindingSummary>,
    Vec<FindingSummary>,
    Vec<FindingSummary>,
) {
    let mut new_findings = Vec::new();
    let mut resolved_findings = Vec::new();
    let mut carried_findings = Vec::new();
    for (key, finding) in current {
        if baseline.contains_key(key) {
            carried_findings.push(finding.clone());
        } else {
            new_findings.push(finding.clone());
        }
    }
    for (key, finding) in baseline {
        if !current.contains_key(key) {
            resolved_findings.push(finding.clone());
        }
    }
    new_findings.sort_by(|a, b| a.key.cmp(&b.key));
    resolved_findings.sort_by(|a, b| a.key.cmp(&b.key));
    carried_findings.sort_by(|a, b| a.key.cmp(&b.key));
    (new_findings, resolved_findings, carried_findings)
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

fn resolve(repo: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo.join(path)
    }
}

fn load_json(path: &Path) -> Result<Value> {
    const LIMIT: u64 = 16 * 1024 * 1024;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > LIMIT {
        anyhow::bail!("invalid or oversized JSON evidence: {}", path.display());
    }
    let mut text = String::new();
    (&file).take(LIMIT + 1).read_to_string(&mut text)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !named.is_file()
        || text.len() as u64 != before.len()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        anyhow::bail!("JSON evidence changed during read: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != named.dev()
            || before.ino() != named.ino()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            anyhow::bail!("JSON evidence identity changed: {}", path.display());
        }
    }
    validation::parse_json_value_strict(&text).with_context(|| format!("parse {}", path.display()))
}

fn string_set(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
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
