//! Freeze reusable async ownership proof independently of runtime permissions.
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

use crate::policy::{ASYNC_API_ID, AsyncApiRules, CompiledPolicy, TrafficPolicy};

pub(super) fn validate_proposal(value: &serde_yaml::Value, revision: Option<&str>) -> Result<()> {
    let Some(apis) = value
        .get("async_api")
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return Ok(());
    };
    for (_, scenarios) in apis {
        let scenarios = scenarios
            .as_sequence()
            .map(Vec::as_slice)
            .unwrap_or_else(|| std::slice::from_ref(scenarios));
        for scenario in scenarios {
            if let Some(ownership) = scenario.get("ownership").filter(|value| !value.is_null()) {
                let mut local = serde_yaml::Mapping::new();
                if let Some(proof) = ownership.get("proof") {
                    local.insert("proof".into(), proof.clone());
                }
                crate::policy::require_source_proof(&mut local.into(), revision)
                    .context("async ownership proposal requires its own local Source proof")?;
            }
        }
    }
    Ok(())
}

pub(super) fn capture(document: &TrafficPolicy) -> Result<BTreeMap<String, AsyncApiRules>> {
    Ok(crate::policy::expand_policy(document)?
        .async_api
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, scenarios)| scenarios.iter().any(|rule| rule.ownership.is_some()))
        .collect())
}

pub(super) fn verify(
    rules: &BTreeMap<String, AsyncApiRules>,
    policy: &CompiledPolicy,
) -> Result<()> {
    let document = TrafficPolicy {
        async_api: Some(rules.clone()),
        ..Default::default()
    };
    crate::policy::require_source_proofs(&document)?;
    let compiled = crate::policy::compile_async_api(rules)?;
    for (api, scenarios) in compiled {
        let current = policy
            .async_api
            .get(&api)
            .context("plan async Source proof lost its runtime API rule")?;
        ensure!(
            crate::policy::async_rules_fingerprint(&scenarios)
                == crate::policy::async_rules_fingerprint(current),
            "plan async Source proof belongs to different runtime ownership permissions"
        );
    }
    Ok(())
}

pub(super) fn summary(
    rules: &BTreeMap<String, AsyncApiRules>,
    selected: &BTreeSet<String>,
) -> Vec<String> {
    rules
        .iter()
        .filter(|(api, _)| {
            selected.contains(ASYNC_API_ID) || selected.contains(&format!("{ASYNC_API_ID}:{api}"))
        })
        .flat_map(|(api, scenarios)| {
            scenarios
                .iter()
                .enumerate()
                .filter_map(move |(index, rule)| {
                    let proof = rule.ownership.as_ref()?.proof.as_ref()?;
                    Some(format!(
                        "{api} scenario {index}: {}: {}",
                        proof.source, proof.fact
                    ))
                })
        })
        .collect()
}
