//! One effective policy and truthful outcomes for library and CLI audits.

use super::policy::AuditMode;
use crate::model::{
    Finding, PolicySummary, Report, ReportDecision, ReportRatchet, PAPER_EDITION, SCHEMA_VERSION,
    STANDARD_VERSION, TARGET_STACK_ID,
};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct ResolvedPolicy {
    pub(super) summary: PolicySummary,
    pub(super) fingerprint: String,
    root: PathBuf,
    source_sha256: Option<String>,
}

impl ResolvedPolicy {
    pub(super) fn require_current(&self, root: &Path) -> Result<()> {
        if root.canonicalize()? != self.root {
            bail!("resolved audit policy belongs to a different repository");
        }
        require_control_directory(root)?;
        if source_digest(read_source(&root.join("agent/audit-policy.toml"))?.as_deref())
            != self.source_sha256
        {
            bail!("repository audit policy changed after resolution");
        }
        Ok(())
    }
}

fn require_control_directory(root: &Path) -> Result<()> {
    let agent = root.join("agent");
    match std::fs::symlink_metadata(&agent) {
        Ok(metadata) if !metadata.is_dir() => bail!(
            "audit control directory must be a directory: {}",
            agent.display()
        ),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect audit control directory"),
    }
    Ok(())
}

pub(super) fn read_source(path: &Path) -> Result<Option<String>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect audit input {}", path.display()))
        }
    };
    if !metadata.is_file() {
        bail!("audit input must be a regular file: {}", path.display());
    }
    std::fs::read_to_string(path)
        .map(Some)
        .with_context(|| format!("read audit input {}", path.display()))
}

fn source_digest(text: Option<&str>) -> Option<String> {
    text.map(|text| format!("sha256:{:x}", Sha256::digest(text.as_bytes())))
}

#[derive(Deserialize)]
struct PolicyFile {
    #[serde(default = "default_minimum_score")]
    minimum_score: i32,
    #[serde(default = "default_fail_on")]
    fail_on: Vec<String>,
    #[serde(default = "default_advisory_on")]
    advisory_on: Vec<String>,
}

fn default_fail_on() -> Vec<String> {
    vec!["critical".into(), "high".into()]
}

fn default_advisory_on() -> Vec<String> {
    vec!["medium".into(), "low".into()]
}

fn default_minimum_score() -> i32 {
    85
}

/// All scanners currently use the repository policy. An explicit source must
/// identify that same existing file, never a partially consumed alternate policy.
pub fn resolve_policy(
    root: &Path,
    explicit_path: Option<&str>,
    minimum_score: Option<i32>,
    fail_on: &[String],
    mode: AuditMode,
) -> Result<ResolvedPolicy> {
    require_control_directory(root)?;
    let path = root.join("agent/audit-policy.toml");
    if let Some(explicit) = explicit_path {
        let canonical = path
            .canonicalize()
            .context("resolve repository audit policy")?;
        let explicit = Path::new(explicit);
        let selected = [explicit.to_path_buf(), root.join(explicit)]
            .into_iter()
            .filter_map(|candidate| candidate.canonicalize().ok())
            .any(|candidate| candidate == canonical && candidate.is_file());
        if !selected {
            bail!(
                "unsupported audit policy source: --policy must identify {}",
                path.display()
            );
        }
    }
    let text = read_source(&path)?;
    let parsed = match text.as_deref() {
        Some(text) => toml::from_str::<PolicyFile>(text)
            .with_context(|| format!("invalid audit policy {}", path.display()))?,
        None => PolicyFile {
            minimum_score: default_minimum_score(),
            fail_on: default_fail_on(),
            advisory_on: default_advisory_on(),
        },
    };
    validate_score(parsed.minimum_score)?;
    validate_severities("fail_on", &parsed.fail_on)?;
    validate_severities("advisory_on", &parsed.advisory_on)?;
    validate_severities("--fail-on", fail_on)?;
    let minimum_score =
        effective_score_floor(parsed.minimum_score, minimum_score).map_err(anyhow::Error::msg)?;
    validate_score(minimum_score)?;
    let mut effective_fail_on = parsed.fail_on;
    effective_fail_on.extend_from_slice(fail_on);
    let mut fail_on = effective_fail_on;
    fail_on.sort();
    fail_on.dedup();
    let mut advisory_on = parsed.advisory_on;
    advisory_on.retain(|severity| !fail_on.contains(severity));
    advisory_on.sort();
    advisory_on.dedup();
    let summary = PolicySummary {
        path: path.display().to_string(),
        minimum_score,
        fail_on,
        advisory_on,
        mode: Some(mode.as_str().into()),
        standard_version: Some(STANDARD_VERSION.into()),
        auditor_version: Some(env!("CARGO_PKG_VERSION").into()),
        schema_version: Some(SCHEMA_VERSION.into()),
        paper_edition: Some(PAPER_EDITION.into()),
        target_stack: Some(TARGET_STACK_ID.into()),
    };
    // Enforcement mode belongs to the report fingerprint. Excluding it here
    // permits an accepted advisory baseline to be evaluated in ratchet mode.
    let source_sha256 = source_digest(text.as_deref());
    let fingerprint = effective_policy_fingerprint(source_sha256.as_deref(), &summary)?;
    Ok(ResolvedPolicy {
        summary,
        fingerprint,
        root: root.canonicalize()?,
        source_sha256,
    })
}

fn effective_policy_fingerprint(
    source_sha256: Option<&str>,
    summary: &PolicySummary,
) -> Result<String> {
    let fingerprint = serde_json::json!({
        "format": "jankurai-effective-audit-policy-v1",
        "source_sha256": source_sha256,
        "minimum_score": summary.minimum_score,
        "fail_on": summary.fail_on,
        "advisory_on": summary.advisory_on,
        "auditor_version": env!("CARGO_PKG_VERSION"),
        "schema_version": SCHEMA_VERSION,
        "standard_version": STANDARD_VERSION,
    });
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&fingerprint)?)
    ))
}

/// Older reports fingerprinted only the source file. Retain that baseline only
/// when its source AND recorded effective settings agree with the current run.
/// This compatibility check grants no execution authority to either report.
pub(super) fn matches_legacy_policy(report: &Report, baseline: &serde_json::Value) -> Result<bool> {
    let Some(policy) = report.policy.as_ref() else {
        return Ok(false);
    };
    let source_sha256 = source_digest(
        read_source(&Path::new(&report.repo).join("agent/audit-policy.toml"))?.as_deref(),
    );
    let old_fingerprint = source_sha256.clone().unwrap_or_else(super::missing_sha256);
    if baseline["policy_fingerprint"].as_str() != Some(old_fingerprint.as_str())
        || effective_policy_fingerprint(source_sha256.as_deref(), policy)?
            != report.policy_fingerprint
        || baseline["auditor_version"].as_str() != Some(report.auditor_version.as_str())
        || baseline["policy"]["minimum_score"].as_i64() != Some(i64::from(policy.minimum_score))
        || baseline["decision"]["minimum_score"].as_i64() != Some(i64::from(policy.minimum_score))
    {
        return Ok(false);
    }
    let severities = |field: &str| -> Option<Vec<String>> {
        let mut values = baseline["policy"][field]
            .as_array()?
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()?;
        validate_severities(field, &values).ok()?;
        values.sort();
        values.dedup();
        Some(values)
    };
    let Some(fail_on) = severities("fail_on") else {
        return Ok(false);
    };
    let Some(mut advisory_on) = severities("advisory_on") else {
        return Ok(false);
    };
    advisory_on.retain(|severity| !fail_on.contains(severity));
    Ok(fail_on == policy.fail_on && advisory_on == policy.advisory_on)
}

pub fn effective_score_floor(policy: i32, requested: Option<i32>) -> Result<i32, &'static str> {
    if !(0..=100).contains(&policy) || requested.is_some_and(|floor| !(0..=100).contains(&floor)) {
        return Err("score floors must be integers from 0 through 100");
    }
    Ok(policy.max(requested.unwrap_or(policy)))
}

fn validate_score(score: i32) -> Result<()> {
    if !(0..=100).contains(&score) {
        bail!("invalid audit policy minimum_score {score}; expected 0..=100");
    }
    Ok(())
}

fn validate_severities(field: &str, severities: &[String]) -> Result<()> {
    for severity in severities {
        if !matches!(
            severity.as_str(),
            "critical" | "high" | "medium" | "low" | "info"
        ) {
            bail!("invalid audit policy severity `{severity}` in {field}; expected critical, high, medium, low, or info");
        }
    }
    Ok(())
}

pub fn report_decision(score: i32, findings: &[Finding], policy: &PolicySummary) -> ReportDecision {
    let hard_findings = findings
        .iter()
        .filter(|finding| policy.fail_on.contains(&finding.severity))
        .count();
    let passed = score >= policy.minimum_score && hard_findings == 0;
    ReportDecision {
        status: if passed { "pass".into() } else { "fail".into() },
        minimum_score: policy.minimum_score,
        passed,
        hard_findings,
        soft_findings: findings.len().saturating_sub(hard_findings),
        ratchet: Some(ReportRatchet {
            baseline_score: score,
            allowed_drop: 0,
            passed,
            score_delta: 0,
            baseline_report_fingerprint: super::missing_sha256(),
            baseline_input_fingerprint: super::missing_sha256(),
            baseline_policy_fingerprint: super::missing_sha256(),
            new_caps: vec![],
            new_hard_findings: vec![],
            policy_changed: false,
        }),
    }
}

/// Refresh every derived assessment. Release mode remains incomplete until
/// `finalize_release` evaluates its required proof inputs.
pub fn finalize(report: &mut Report, baseline: Option<&str>) -> Result<()> {
    assess(report, baseline, false)
}

/// Evaluate release proof inputs before completing the release assessment.
pub fn finalize_release(
    report: &mut Report,
    baseline: Option<&str>,
    receipts: Option<&str>,
    evidence: Option<&str>,
) -> Result<()> {
    let findings = super::release_proof_findings(Path::new(&report.repo), receipts, evidence)?;
    let release_complete = findings.is_empty();
    if !release_complete {
        report.findings.extend(findings);
        super::rebuild_agent_fix_queue(report);
    }
    assess(report, baseline, release_complete)
}

fn assess(report: &mut Report, baseline: Option<&str>, release_complete: bool) -> Result<()> {
    let policy = report
        .policy
        .as_ref()
        .context("audit produced no effective policy")?;
    let mode = AuditMode::parse(policy.mode.as_deref().unwrap_or("standard"))?;
    let mut decision = report_decision(report.score, &report.findings, policy);
    if let Some(path) = baseline {
        let ratchet = super::baseline::compare_report_to_baseline(report, Path::new(path))?;
        if matches!(mode, AuditMode::Ratchet | AuditMode::Release) && !ratchet.passed {
            decision.status = "fail".into();
            decision.passed = false;
        }
        decision.ratchet = Some(ratchet);
    } else if mode == AuditMode::Ratchet {
        decision.passed = false;
        if let Some(ratchet) = decision.ratchet.as_mut() {
            ratchet.passed = false;
        }
    }
    if mode == AuditMode::Release && !release_complete {
        decision.passed = false;
    }
    let blockers = report
        .findings
        .iter()
        .filter(|finding| {
            matches!(finding.severity.as_str(), "critical" | "high")
                || policy.fail_on.contains(&finding.severity)
        })
        .map(|finding| {
            format!(
                "{} on {}",
                finding.rule_id.as_deref().unwrap_or(&finding.check_id),
                finding.path
            )
        })
        .collect::<Vec<_>>();
    // A weak score policy cannot turn an existing conformance blocker into a
    // passing assessment. Keep its exact severity counts and all diagnostics.
    if !blockers.is_empty() {
        decision.passed = false;
    }
    if mode == AuditMode::Advisory {
        decision.status = "advisory".into();
    } else if !decision.passed {
        decision.status = "fail".into();
    }
    let full_standard = report.scope.mode == "full"
        && mode != AuditMode::Advisory
        && policy.minimum_score >= default_minimum_score()
        && ["critical", "high"]
            .iter()
            .all(|severity| policy.fail_on.iter().any(|value| value == severity));
    let conforms = decision.passed && blockers.is_empty() && full_standard;
    report.observed_conformance_level = if conforms {
        "HL3"
    } else if mode == AuditMode::Advisory || report.scope.mode != "full" {
        "HL1"
    } else {
        "HL2"
    }
    .into();
    // Advisory reports retain blockers for review without claiming conformance
    // or instructing their explicitly nonblocking command to fail.
    report.conformance_decision = if mode == AuditMode::Advisory {
        "review"
    } else if !blockers.is_empty() {
        "block"
    } else if conforms {
        "pass"
    } else {
        "review"
    }
    .into();
    report.conformance_blockers = blockers;
    report.decision = Some(decision);
    Ok(())
}

pub fn enforce(report: &Report) -> Result<()> {
    let policy = report
        .policy
        .as_ref()
        .context("audit produced no effective policy")?;
    let mode = AuditMode::parse(policy.mode.as_deref().unwrap_or("standard"))?;
    if report.conformance_decision == "block" {
        bail!(
            "audit conformance blocked in {} mode: blockers={}",
            mode.as_str(),
            report.conformance_blockers.len()
        );
    }
    if mode == AuditMode::Advisory {
        return Ok(());
    }
    let decision = report
        .decision
        .as_ref()
        .context("non-advisory audit produced no decision")?;
    if !decision.passed {
        bail!("audit decision failed in {} mode: status={} score={} minimum_score={} hard_findings={}", mode.as_str(), decision.status, report.score, decision.minimum_score, decision.hard_findings);
    }
    Ok(())
}
