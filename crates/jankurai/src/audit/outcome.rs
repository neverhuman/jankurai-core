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
        if source_digest(read_source(&root.join("agent/audit-policy.toml"))?.as_deref())
            != self.source_sha256
        {
            bail!("repository audit policy changed after resolution");
        }
        Ok(())
    }
}

fn read_source(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).with_context(|| format!("read audit policy {}", path.display())),
    }
}

fn source_digest(text: Option<&str>) -> Option<String> {
    text.map(|text| format!("sha256:{:x}", Sha256::digest(text.as_bytes())))
}

#[derive(Deserialize)]
struct PolicyFile {
    #[serde(default = "default_minimum_score")]
    minimum_score: i32,
    #[serde(default)]
    fail_on: Vec<String>,
    #[serde(default)]
    advisory_on: Vec<String>,
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
            fail_on: vec!["critical".into(), "high".into()],
            advisory_on: vec!["medium".into(), "low".into()],
        },
    };
    validate_score(parsed.minimum_score)?;
    validate_severities("fail_on", &parsed.fail_on)?;
    validate_severities("advisory_on", &parsed.advisory_on)?;
    validate_severities("--fail-on", fail_on)?;
    let minimum_score = minimum_score.unwrap_or(parsed.minimum_score);
    validate_score(minimum_score)?;
    let mut fail_on = if fail_on.is_empty() {
        parsed.fail_on
    } else {
        fail_on.to_vec()
    };
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
    let fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&fingerprint)?)
    );
    Ok(ResolvedPolicy {
        summary,
        fingerprint,
        root: root.canonicalize()?,
        source_sha256,
    })
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
    if !findings.is_empty() {
        report.findings.extend(findings);
        super::rebuild_agent_fix_queue(report);
    }
    assess(report, baseline, true)
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
    if !decision.passed {
        decision.status = "fail".into();
    }
    if mode == AuditMode::Advisory {
        decision.status = "advisory".into();
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
    report.conformance_decision = if !blockers.is_empty() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{run_audit_timed_with_policy, AuditOptions};

    #[test]
    fn mode_prerequisites_prevent_intermediate_acceptance() {
        let root = tempfile::tempdir().unwrap();
        for mode in [AuditMode::Ratchet, AuditMode::Release] {
            let policy = resolve_policy(root.path(), None, None, &[], mode).unwrap();
            let (mut report, _) =
                run_audit_timed_with_policy(root.path(), &[], AuditOptions::default(), policy)
                    .unwrap();
            report.score = 100;
            report.findings.clear();
            report.caps_applied.clear();
            finalize(&mut report, None).unwrap();
            assert!(!report.decision.as_ref().unwrap().passed);
            assert_eq!(report.conformance_decision, "review");
            assert!(enforce(&report).is_err());
            if mode == AuditMode::Ratchet {
                assert!(
                    !report
                        .decision
                        .as_ref()
                        .unwrap()
                        .ratchet
                        .as_ref()
                        .unwrap()
                        .passed
                );
                let baseline = root.path().join("baseline.json");
                std::fs::write(&baseline, serde_json::to_vec(&report).unwrap()).unwrap();
                finalize(&mut report, baseline.to_str()).unwrap();
            } else {
                let mut missing = report.clone();
                finalize_release(&mut missing, None, None, None).unwrap();
                assert_eq!(missing.conformance_decision, "block");
                assert!(enforce(&missing).is_err());
                let receipt = serde_json::json!({
                    "lane": "fixture", "command": "fixture", "exit_code": 0,
                    "elapsed_ms": 1, "artifacts": [],
                });
                std::fs::write(root.path().join("receipt.json"), receipt.to_string()).unwrap();
                finalize_release(&mut report, None, Some("receipt.json"), None).unwrap();
            }
            assert!(report.decision.as_ref().unwrap().passed);
            assert_eq!(report.conformance_decision, "pass");
            enforce(&report).unwrap();
        }
    }

    #[test]
    fn resolved_policy_rejects_other_repositories_and_source_drift() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let resolve =
            || resolve_policy(first.path(), None, None, &[], AuditMode::Standard).unwrap();
        let error =
            run_audit_timed_with_policy(second.path(), &[], AuditOptions::default(), resolve())
                .unwrap_err();
        assert!(error.to_string().contains("different repository"));
        let previous = resolve();
        std::fs::create_dir(first.path().join("agent")).unwrap();
        std::fs::write(
            first.path().join("agent/audit-policy.toml"),
            "minimum_score = 90\n",
        )
        .unwrap();
        let error =
            run_audit_timed_with_policy(first.path(), &[], AuditOptions::default(), previous)
                .unwrap_err();
        assert!(error.to_string().contains("changed after resolution"));
        run_audit_timed_with_policy(first.path(), &[], AuditOptions::default(), resolve()).unwrap();
    }
}
