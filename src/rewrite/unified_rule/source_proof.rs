//! Source explanations are plan evidence, separate from published runtime policy.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::policy::{PolicyRule, TrafficPolicy};

/// Check the submitted proposal before owner-local inheritance resolves it.
/// An explicit state-epoch permission requires its own local Source evidence.
pub(super) fn validate_proposal(input: &str) -> Result<()> {
    let raw: serde_yaml::Value = serde_yaml::from_str(input)?;
    let value = if raw.get("format").and_then(serde_yaml::Value::as_str)
        == Some("traffic-policy-change/v1")
    {
        raw.get("policy")
            .context("policy change is missing runtime declarations")?
    } else {
        &raw
    };
    let revision = value
        .get("source_revision")
        .and_then(serde_yaml::Value::as_str);
    let mut rules = vec![];
    if value.get("rules").is_some() || value.get("format").is_some() {
        if let Some(entries) = value.get("rules").and_then(serde_yaml::Value::as_sequence) {
            rules.extend(entries.iter());
        }
        if let Some(entries) = value
            .get("redis")
            .and_then(|redis| redis.get("rules"))
            .and_then(serde_yaml::Value::as_sequence)
        {
            rules.extend(entries.iter());
        }
    } else if let Some(entries) = value.as_sequence() {
        rules.extend(entries.iter());
    } else if value.get("effect").is_some() {
        rules.push(value);
    }
    for rule in rules {
        crate::policy::require_source_proof(&mut rule.clone(), revision)?;
    }
    if let Some(keys) = value
        .get("redis")
        .and_then(|redis| redis.get("keys"))
        .and_then(serde_yaml::Value::as_mapping)
    {
        for (pattern, entry) in keys {
            if ![
                "append_stream",
                "read_commutation",
                "expiry_refresh",
                "read_back",
                "finite_sharing",
            ]
            .iter()
            .any(|behavior| entry.get(*behavior).is_some())
            {
                continue;
            }
            // A compact key is the authored permission boundary. Preserve its
            // own proof before expansion produces internal native owners.
            let mut local = serde_yaml::Mapping::new();
            if let Some(proof) = entry.get("proof") {
                local.insert("proof".into(), proof.clone());
            }
            crate::policy::require_source_proof(&mut serde_yaml::Value::Mapping(local), revision)
                .with_context(|| {
                format!("Redis key {pattern:?} behavior requires local Source proof")
            })?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SourceProofSnapshot {
    rules: Vec<PolicyRule>,
    sha256: String,
}

#[cfg(test)]
mod tests;

impl SourceProofSnapshot {
    pub(super) fn capture(document: &TrafficPolicy) -> Result<Self> {
        crate::policy::require_source_proofs(document)?;
        let rules = crate::policy::effective_rules(document)?;
        let sha256 = crate::policy_evidence::digest(&serde_json::to_vec(&rules)?);
        Ok(Self { rules, sha256 })
    }

    pub(super) fn verify(&self, policy: &crate::policy::CompiledPolicy) -> Result<()> {
        ensure!(
            crate::policy_evidence::digest(&serde_json::to_vec(&self.rules)?) == self.sha256,
            "plan Source proof snapshot changed"
        );
        let document = TrafficPolicy {
            rules: self.rules.clone(),
            ..Default::default()
        };
        crate::policy::require_source_proofs(&document)?;
        for rule in &self.rules {
            match rule {
                PolicyRule::Native(rule) => {
                    let runtime = policy
                        .native
                        .iter()
                        .find(|current| current.rule.id == rule.id)
                        .context("plan Source proof lost its runtime rule")?;
                    ensure!(
                        crate::policy::compile_native(rule)?.fingerprint == runtime.fingerprint,
                        "plan Source proof belongs to a different runtime permission"
                    );
                }
                PolicyRule::Value(rule) => {
                    let runtime = policy
                        .rules
                        .iter()
                        .find(|current| current.rule.id == rule.id)
                        .context("plan Source proof lost its runtime value rule")?;
                    ensure!(
                        crate::policy::compile_rule(rule)?.fingerprint == runtime.fingerprint,
                        "plan Source proof belongs to a different value permission"
                    );
                }
            }
        }
        Ok(())
    }

    pub(super) fn summary(&self, selected: &std::collections::BTreeSet<String>) -> String {
        self.rules
            .iter()
            .filter(|rule| selected.contains(rule.id()))
            .filter_map(|rule| rule.proof())
            .map(|proof| format!("{}: {}", proof.source, proof.fact))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
