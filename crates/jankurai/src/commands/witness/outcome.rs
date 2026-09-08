use super::{ProofBindWitnessSummary, RouteDecision};
use crate::audit::baseline::compare_report_to_baseline;
use crate::commands::context_data::push_unique;
use crate::commands::score::{finding_summary, FindingSummary};
use crate::model::{Finding, Report};
use crate::validation::{self, ArtifactSchema};
use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) struct Assessment {
    pub baseline_score: Option<i32>,
    pub score_delta: Option<i32>,
    pub caps_added: Vec<String>,
    pub new_findings: Vec<FindingSummary>,
    pub resolved_findings: Vec<FindingSummary>,
    pub carried_findings: Vec<FindingSummary>,
    pub decision: &'static str,
    pub observed_conformance_level: String,
    pub conformance_blockers: Vec<String>,
    pub review_reasons: Vec<String>,
}

pub(super) fn assess(
    report: &Report,
    baseline_path: Option<&Path>,
    routes: &[RouteDecision],
    proofbind: &ProofBindWitnessSummary,
    missing_evidence: &mut Vec<String>,
) -> Result<Assessment> {
    let mut blockers = report.conformance_blockers.clone();
    let mut review = Vec::new();
    for route in routes {
        if route.decision != "require-proof"
            || [
                route.owner.as_str(),
                route.owner_route.as_str(),
                route.test_command.as_str(),
                route.proof_lane.as_str(),
            ]
            .iter()
            .any(|value| value.is_empty() || *value == "unmapped")
        {
            push_unique(
                missing_evidence,
                format!("route for `{}` is blocked: {}", route.path, route.reason),
            );
        }
    }
    if proofbind.missing_obligation_count > 0 {
        push_unique(
            missing_evidence,
            format!(
                "proofbind reports {} semantic proof obligation(s) still missing receipt evidence",
                proofbind.missing_obligation_count
            ),
        );
    }
    match proofbind.verdict.as_str() {
        "not_run" if routes.is_empty() && proofbind.changed_surface_count == 0 => {}
        "pass" => {
            if !routes.is_empty() && proofbind.changed_surface_count == 0 {
                push_unique(
                    missing_evidence,
                    "proofbind reports no changed surfaces for routed changes",
                );
            }
            if proofbind.changed_surface_count > 0 && proofbind.satisfied_obligation_count == 0 {
                push_unique(
                    missing_evidence,
                    "proofbind changed surfaces have no satisfied obligations",
                );
            }
        }
        "review" => review.push("proofbind requires review".into()),
        other => push_unique(
            missing_evidence,
            format!("proofbind assessment is `{other}`"),
        ),
    }
    for missing in missing_evidence.iter() {
        push_unique(&mut blockers, missing.clone());
    }
    match report.decision.as_ref() {
        None => push_unique(&mut blockers, "audit produced no decision"),
        Some(decision)
            if !decision.passed || !matches!(decision.status.as_str(), "pass" | "advisory") =>
        {
            push_unique(&mut blockers, "audit decision did not pass")
        }
        Some(_) => {}
    }
    let strong_policy = if let Some(policy) = report.policy.as_ref() {
        if !crate::audit::outcome::report_decision(report.score, &report.findings, policy).passed {
            push_unique(
                &mut blockers,
                "current score or findings fail the effective audit policy",
            );
        }
        policy.minimum_score >= 85
            && policy.mode.as_deref() != Some("advisory")
            && ["critical", "high"]
                .iter()
                .all(|severity| policy.fail_on.iter().any(|value| value == severity))
    } else {
        push_unique(&mut blockers, "audit produced no effective policy");
        false
    };
    for finding in &report.findings {
        if matches!(finding.severity.as_str(), "critical" | "high") {
            push_unique(
                &mut blockers,
                format!(
                    "{} on {}",
                    finding.rule_id.as_deref().unwrap_or(&finding.check_id),
                    finding.path
                ),
            );
        }
    }
    for cap in &report.caps_applied {
        push_unique(&mut blockers, format!("audit applies cap `{cap}`"));
    }
    match report.conformance_decision.as_str() {
        "pass" => {}
        "review" => review.push("audit conformance requires review".into()),
        other => push_unique(
            &mut blockers,
            format!("audit conformance assessment is `{other}`"),
        ),
    }
    if report.scope.mode != "full" {
        review.push(format!(
            "audit scope `{}` cannot establish full conformance",
            report.scope.mode
        ));
    }
    if !strong_policy {
        review.push("effective audit policy cannot establish full conformance".into());
    }
    let levels = ["HL0", "HL1", "HL2", "HL3", "HL4", "HL5"];
    let source_level = levels
        .iter()
        .position(|level| *level == report.observed_conformance_level)
        .unwrap_or_else(|| {
            push_unique(&mut blockers, "audit produced an invalid conformance level");
            0
        });
    if source_level < 3 {
        review.push(format!(
            "audit establishes only {}",
            report.observed_conformance_level
        ));
    }

    let baseline = if let Some(path) = baseline_path {
        let value = super::receipts::load_json(path)?;
        validation::validate_value(Path::new(&report.repo), ArtifactSchema::RepoScore, &value)?;
        if !value
            .get("score")
            .and_then(Value::as_i64)
            .is_some_and(|score| (0..=100).contains(&score))
        {
            bail!("witness baseline score must be in 0..=100");
        }
        if value
            .get("scope")
            .and_then(|scope| scope.get("mode"))
            .and_then(Value::as_str)
            != Some("full")
        {
            bail!("witness baseline must describe a full audit");
        }
        let ratchet = compare_report_to_baseline(report, path)?;
        if super::receipts::load_json(path)? != value {
            bail!("witness baseline changed during assessment");
        }
        Some((value, ratchet))
    } else {
        review.push("attach a valid full-audit baseline before merging".into());
        None
    };
    let baseline_score = baseline.as_ref().map(|(_, ratchet)| ratchet.baseline_score);
    let score_delta = baseline.as_ref().map(|(_, ratchet)| ratchet.score_delta);
    let ratchet_failed = baseline
        .as_ref()
        .is_some_and(|(_, ratchet)| !ratchet.passed);
    if ratchet_failed {
        push_unique(
            &mut blockers,
            "audit baseline ratchet rejected score, caps, hard findings, policy, or versions",
        );
    }
    let current_findings = finding_map_from_report(report);
    let baseline_findings = baseline
        .as_ref()
        .map(|(value, _)| finding_map_from_value(value))
        .unwrap_or_default();
    let (new_findings, resolved_findings, carried_findings) =
        finding_changes(&baseline_findings, &current_findings);
    let baseline_caps = baseline
        .as_ref()
        .map(|(value, _)| string_set(value.get("caps_applied")))
        .unwrap_or_default();
    let current_caps: BTreeSet<String> = report.caps_applied.iter().cloned().collect();
    let caps_added: Vec<String> = current_caps.difference(&baseline_caps).cloned().collect();
    if !new_findings.is_empty() || !caps_added.is_empty() {
        review.push("review new findings and caps before merging".into());
    }
    let decision = if ratchet_failed {
        "ratchet_fail"
    } else if !blockers.is_empty() {
        "block"
    } else if !review.is_empty() {
        "review"
    } else {
        "pass"
    };
    let maximum_level = if report.scope.mode != "full" {
        1
    } else if decision == "pass" {
        3
    } else {
        2
    };
    Ok(Assessment {
        baseline_score,
        score_delta,
        caps_added,
        new_findings,
        resolved_findings,
        carried_findings,
        decision,
        observed_conformance_level: levels[source_level.min(maximum_level)].into(),
        conformance_blockers: blockers,
        review_reasons: review,
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

fn string_set(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> (tempfile::TempDir, Report, std::path::PathBuf) {
        let repo = tempfile::tempdir().unwrap();
        let mut report = crate::audit::run_audit(repo.path(), &[]).unwrap();
        report.findings.clear();
        report.caps_applied.clear();
        report.score = 100;
        report.raw_score = 100;
        crate::audit::outcome::finalize(&mut report, None).unwrap();
        report.report_fingerprint = crate::audit::report_fingerprint(&report);
        let path = repo.path().join("baseline.json");
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        (repo, report, path)
    }

    fn proof() -> ProofBindWitnessSummary {
        ProofBindWitnessSummary {
            changed_surface_count: 0,
            satisfied_obligation_count: 0,
            missing_obligation_count: 0,
            verdict: "not_run".into(),
        }
    }

    #[test]
    fn partial_and_missing_assessment_cannot_elevate_source_conformance() {
        let (_repo, report, baseline) = passing();
        let check =
            |value: &Report| assess(value, Some(&baseline), &[], &proof(), &mut vec![]).unwrap();
        let accepted = check(&report);
        assert_eq!(accepted.decision, "pass");
        assert_eq!(accepted.observed_conformance_level, "HL3");
        for mode in ["changed", "changed-fast"] {
            let mut partial = report.clone();
            partial.scope.mode = mode.into();
            let result = check(&partial);
            assert_eq!(result.decision, "review");
            assert_eq!(result.observed_conformance_level, "HL1");
        }
        let mut missing = report.clone();
        missing.decision = None;
        assert!(check(&missing)
            .conformance_blockers
            .iter()
            .any(|reason| reason.contains("no decision")));
        missing = report.clone();
        missing.policy = None;
        assert_eq!(check(&missing).decision, "block");
        let mut contradictory = report.clone();
        contradictory.score = 0;
        assert!(contradictory.decision.as_ref().unwrap().passed);
        assert_ne!(check(&contradictory).decision, "pass");
        assert!(check(&contradictory)
            .conformance_blockers
            .iter()
            .any(|reason| reason.contains("effective audit policy")));
        let mut lower = report.clone();
        lower.observed_conformance_level = "HL1".into();
        assert_eq!(check(&lower).observed_conformance_level, "HL1");
        assert_eq!(check(&lower).decision, "review");
    }

    #[test]
    fn routes_and_semantic_obligations_are_assessed_before_merge_decision() {
        let (_repo, report, baseline) = passing();
        let mut route = RouteDecision {
            path: "src/lib.rs".into(),
            owner: "unmapped".into(),
            owner_route: "unmapped".into(),
            test_command: "cargo test".into(),
            proof_lane: "fast".into(),
            decision: "block".into(),
            reason: "path has no owner-map route".into(),
        };
        let mut evidence = ProofBindWitnessSummary {
            changed_surface_count: 1,
            satisfied_obligation_count: 1,
            missing_obligation_count: 0,
            verdict: "pass".into(),
        };
        let check = |route: &RouteDecision, proof: &ProofBindWitnessSummary| {
            assess(
                &report,
                Some(&baseline),
                std::slice::from_ref(route),
                proof,
                &mut vec![],
            )
            .unwrap()
        };
        assert!(check(&route, &evidence)
            .conformance_blockers
            .iter()
            .any(|reason| reason.contains("route for")));
        route.owner = "tools".into();
        route.owner_route = "src/".into();
        route.decision = "require-proof".into();
        assert_eq!(check(&route, &evidence).decision, "pass");
        evidence.missing_obligation_count = 1;
        assert_eq!(check(&route, &evidence).decision, "block");
        evidence.missing_obligation_count = 0;
        evidence.satisfied_obligation_count = 0;
        assert_eq!(check(&route, &evidence).decision, "block");
        assert_eq!(check(&route, &proof()).decision, "block");
        evidence.changed_surface_count = 0;
        assert!(check(&route, &evidence)
            .conformance_blockers
            .iter()
            .any(|reason| reason.contains("no changed surfaces for routed changes")));
        assert_eq!(
            assess(&report, Some(&baseline), &[], &evidence, &mut vec![])
                .unwrap()
                .decision,
            "pass"
        );
    }
}
