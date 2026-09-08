use super::{ProofBindWitnessSummary, ProofReceiptSummary};
use crate::model::ProofReceipt;
use crate::validation::{self, ArtifactSchema};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn load_proof_receipts(
    repo: &Path,
    path: Option<&str>,
) -> Result<Vec<ProofReceiptSummary>> {
    let Some(path) = path else {
        return Ok(vec![]);
    };
    let path = resolve(repo, path);
    if !path.exists() {
        return Ok(vec![]);
    }
    let mut entries = Vec::new();
    if path.is_dir() {
        for entry in fs::read_dir(&path).with_context(|| format!("read {}", path.display()))? {
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
        let text =
            fs::read_to_string(&entry).with_context(|| format!("read {}", entry.display()))?;
        let value: Value =
            serde_json::from_str(&text).with_context(|| format!("parse {}", entry.display()))?;
        validation::validate_value(repo, ArtifactSchema::ProofReceipt, &value)?;
        let receipt: ProofReceipt = serde_json::from_value(value)?;
        if receipt.exit_code == 0 {
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
            });
        }
    }
    Ok(out)
}

pub(super) fn load_proofbind_summary(
    repo: &Path,
    proof_receipts: Option<&str>,
) -> Result<ProofBindWitnessSummary> {
    let obligations_path = repo.join("target/jankurai/proofbind/obligations.json");
    if !obligations_path.exists() {
        return Ok(ProofBindWitnessSummary {
            changed_surface_count: 0,
            satisfied_obligation_count: 0,
            missing_obligation_count: 0,
            verdict: "not_run".into(),
        });
    }
    let obligations_value = load_json(&obligations_path)?;
    validation::validate_value(
        repo,
        ArtifactSchema::ProofBindObligations,
        &obligations_value,
    )?;
    let receipt_values = load_proof_receipt_values(repo, proof_receipts)?;
    let changed_surface_count = obligations_value
        .get("summary")
        .and_then(|summary| summary.get("changed_surface_count"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    let obligations = obligations_value
        .get("obligations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut satisfied = 0usize;
    let mut missing = 0usize;
    for obligation in &obligations {
        if receipt_values
            .iter()
            .any(|receipt| receipt_satisfies_obligation(obligation, receipt))
        {
            satisfied += 1;
        } else {
            missing += 1;
        }
    }
    let configured_verdict = obligations_value
        .get("summary")
        .and_then(|summary| summary.get("verdict"))
        .and_then(Value::as_str)
        .unwrap_or("review");
    let verdict = if missing == 0 {
        "pass"
    } else {
        configured_verdict
    };
    Ok(ProofBindWitnessSummary {
        changed_surface_count,
        satisfied_obligation_count: satisfied,
        missing_obligation_count: missing,
        verdict: verdict.into(),
    })
}

fn load_proof_receipt_values(repo: &Path, path: Option<&str>) -> Result<Vec<Value>> {
    let Some(path) = path else {
        return Ok(vec![]);
    };
    let path = resolve(repo, path);
    if !path.exists() {
        return Ok(vec![]);
    }
    let mut entries = Vec::new();
    if path.is_dir() {
        for entry in fs::read_dir(&path).with_context(|| format!("read {}", path.display()))? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
                entries.push(entry.path());
            }
        }
        entries.sort();
    } else {
        entries.push(path);
    }
    let mut values = Vec::new();
    for entry in entries {
        let text =
            fs::read_to_string(&entry).with_context(|| format!("read {}", entry.display()))?;
        let value: Value =
            serde_json::from_str(&text).with_context(|| format!("parse {}", entry.display()))?;
        validation::validate_value(repo, ArtifactSchema::ProofReceipt, &value)?;
        if value.get("exit_code").and_then(Value::as_i64).unwrap_or(1) == 0 {
            values.push(value);
        }
    }
    Ok(values)
}

fn receipt_satisfies_obligation(obligation: &Value, receipt: &Value) -> bool {
    let obligation_id = obligation
        .get("obligation_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let proofmark = receipt
        .get("extensions")
        .and_then(|extensions| extensions.get("proofmark"))
        .unwrap_or(&Value::Null);
    if proofmark
        .get("satisfied_obligations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|id| id == obligation_id)
    {
        return true;
    }
    if proofmark
        .get("obligation_results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|result| {
            result
                .get("obligation_id")
                .and_then(Value::as_str)
                .is_some_and(|id| id == obligation_id)
                && result
                    .get("status")
                    .and_then(Value::as_str)
                    .is_some_and(|status| status == "pass")
        })
    {
        return true;
    }
    let lane = receipt
        .get("lane")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if lane == "proofmark-rust" {
        return false;
    }
    let lane_matches = obligation
        .get("required_lanes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|required| required == lane);
    if !lane_matches {
        return false;
    }
    let path = obligation
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let path_matches = receipt
        .get("changed_paths")
        .and_then(Value::as_array)
        .map(|paths| {
            paths
                .iter()
                .filter_map(Value::as_str)
                .any(|changed| changed == path || path.starts_with(&format!("{changed}/")))
        })
        .unwrap_or(true);
    if !path_matches {
        return false;
    }
    let covered_rules = receipt_rules_covered(receipt);
    covered_rules.is_empty()
        || obligation
            .get("rule_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|rule| covered_rules.contains(rule))
}

fn receipt_rules_covered(receipt: &Value) -> BTreeSet<String> {
    receipt
        .get("rules_covered")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            if let Some(rule) = item.as_str() {
                return Some(rule.to_string());
            }
            let status = item
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("covered");
            if !matches!(status, "covered" | "pass" | "satisfied") {
                return None;
            }
            item.get("rule_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn resolve(repo: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo.join(path)
    }
}

pub(super) fn load_json(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}
