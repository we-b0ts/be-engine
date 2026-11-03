//! Source explanations are plan evidence, separate from published runtime policy.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::policy::{PolicyRule, TrafficPolicy};

mod async_ownership;

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
    async_ownership::validate_proposal(value, revision)?;
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
                "read_observation",
                "expiry_refresh",
                "read_back",
                "commands",
                "key_format",
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
    let mut lifetime_requests = Vec::new();
    if let Some(requests) = value
        .get("localcache")
        .and_then(|section| section.get("requests"))
        .and_then(serde_yaml::Value::as_sequence)
    {
        lifetime_requests.extend(requests.iter());
    }
    if let Some(tasks) = value
        .get("process_dependencies")
        .and_then(|section| section.get("tasks"))
        .and_then(serde_yaml::Value::as_mapping)
    {
        for (_, task) in tasks {
            if let Some(requests) = task
                .get("requests")
                .and_then(serde_yaml::Value::as_sequence)
            {
                lifetime_requests.extend(requests.iter());
            }
        }
    }
    for request in lifetime_requests {
        let mut local = serde_yaml::Mapping::new();
        if let Some(proof) = request.get("proof") {
            local.insert("proof".into(), proof.clone());
        }
        crate::policy::require_source_proof(&mut serde_yaml::Value::Mapping(local), revision)
            .context(
                "dependency lifetime plan requires local Source proof for each selected request",
            )?;
    }
    if let Some(apis) = value.get("api").and_then(serde_yaml::Value::as_mapping) {
        for (_, api) in apis {
            for (direction, collection) in [
                ("request", "headers"),
                ("request", "query"),
                ("response", "json"),
                ("response", "headers"),
            ] {
                if let Some(positions) = api
                    .get(direction)
                    .and_then(|side| side.get(collection))
                    .and_then(serde_yaml::Value::as_mapping)
                {
                    for (_, position) in positions {
                        let mut local = serde_yaml::Mapping::new();
                        if let Some(proof) = position.get("proof") {
                            local.insert("proof".into(), proof.clone());
                        }
                        crate::policy::require_source_proof(&mut local.into(), revision).context(
                            "API signature position requires local Source proof in a plan",
                        )?;
                    }
                }
            }
            if let Some(body) = api.get("request").and_then(|side| side.get("body")) {
                let mut local = serde_yaml::Mapping::new();
                if let Some(proof) = body.get("proof") {
                    local.insert("proof".into(), proof.clone());
                }
                crate::policy::require_source_proof(&mut local.into(), revision)
                    .context("API signed body requires local Source proof in a plan")?;
            }
        }
    }
    // Carrier bindings expand through the same typed owners as runtime. Check
    // their complete subtree so codec fields and HTTP path references cannot
    // acquire permission merely by moving outside the legacy rules list.
    let carrier_declarations = value.get("recording").is_some()
        || value.get("http").is_some_and(|http| {
            http.get("requests").is_some() || http.get("response_rewrite").is_some()
        })
        || value
            .get("api")
            .and_then(serde_yaml::Value::as_mapping)
            .is_some_and(|apis| {
                apis.values().any(|api| {
                    api.get("response")
                        .is_some_and(|response| response.get("body").is_some())
                })
            });
    if carrier_declarations
        && value.get("format").and_then(serde_yaml::Value::as_str)
            == Some(crate::policy::POLICY_FORMAT)
    {
        let document: TrafficPolicy = serde_yaml::from_value(value.clone())?;
        for rule in document.rules.iter().filter(|rule| {
            rule.id().starts_with("http.request.")
                || rule.id().starts_with("api.binding.")
                || rule.as_native().is_some_and(|rule| {
                    matches!(
                        rule.effect,
                        crate::policy::NativeEffect::CaptureHttp(_)
                            | crate::policy::NativeEffect::CaptureHttpResponse(_)
                    )
                })
        }) {
            crate::policy::require_source_proof(&mut serde_yaml::to_value(rule)?, revision)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SourceProofSnapshot {
    rules: Vec<PolicyRule>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    async_api: std::collections::BTreeMap<String, crate::policy::AsyncApiRules>,
    sha256: String,
}

#[cfg(test)]
mod tests;

impl SourceProofSnapshot {
    pub(super) fn capture(document: &TrafficPolicy) -> Result<Self> {
        crate::policy::require_source_proofs(document)?;
        let rules = crate::policy::effective_rules(document)?;
        let async_api = async_ownership::capture(document)?;
        let sha256 = Self::identity(&rules, &async_api)?;
        Ok(Self {
            rules,
            async_api,
            sha256,
        })
    }

    pub(super) fn verify(&self, policy: &crate::policy::CompiledPolicy) -> Result<()> {
        ensure!(
            Self::identity(&self.rules, &self.async_api)? == self.sha256,
            "plan Source proof snapshot changed"
        );
        let document = TrafficPolicy {
            rules: self.rules.clone(),
            ..Default::default()
        };
        crate::policy::require_source_proofs(&document)?;
        async_ownership::verify(&self.async_api, policy)?;
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
            .chain(async_ownership::summary(&self.async_api, selected))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn identity(
        rules: &[PolicyRule],
        async_api: &std::collections::BTreeMap<String, crate::policy::AsyncApiRules>,
    ) -> Result<String> {
        // Old persisted plans retain their established digest and decode with
        // an empty optional async snapshot.
        let bytes = if async_api.is_empty() {
            serde_json::to_vec(rules)?
        } else {
            serde_json::to_vec(&(rules, async_api))?
        };
        Ok(crate::policy_evidence::digest(&bytes))
    }
}
