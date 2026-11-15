//! Logical value draft paths and bounded witness aggregation.
use super::*;

#[derive(Default)]
pub(super) struct JsonLocation {
    pointer: String,
    pattern: String,
}

impl JsonLocation {
    fn from_source(source: &traffic_value::Value, pointer: &str) -> Result<Self> {
        traffic_value::path::validate(pointer, false)?;
        let mut location = Self::default();
        let mut value = source;
        for part in pointer.split('/').skip(1) {
            location = match value {
                traffic_value::Value::Array(_) => location.element(part.parse()?),
                _ => location.key(&part.replace("~1", "/").replace("~0", "~")),
            };
            value = value
                .pointer(&format!("/{part}"))
                .context("policy Source location is absent")?;
        }
        Ok(location)
    }
    fn key(&self, key: &str) -> Self {
        let key = key.replace('~', "~0").replace('/', "~1");
        Self {
            pointer: format!("{}/{key}", self.pointer),
            pattern: format!("{}/{key}", self.pattern),
        }
    }

    fn element(&self, index: usize) -> Self {
        Self {
            pointer: format!("{}/{index}", self.pointer),
            pattern: format!("{}/*", self.pattern),
        }
    }
}

impl Drafts {
    pub(super) fn source_findings(
        &mut self,
        bytes: &[u8],
        source: &traffic_value::Value,
        base: &Value,
        witness: &str,
        clocks: AnchorClocks,
    ) -> Result<()> {
        let mut facts = base.clone();
        facts["clocks"] = clocks.observations();
        facts["settings"] = json!({"time":self.time});
        for finding in
            crate::value_extensions::analyze_source(&self.policies, source, bytes, &facts)?
        {
            self.record_finding(&finding, base, witness)?;
            if let Some(proposal) = &finding.proposal {
                let location = JsonLocation::from_source(source, &finding.source_path)?;
                self.push(&location, proposal, witness, &finding)?;
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)] // One bounded walk retains immutable decoding and clock context.
    pub(super) fn collect(
        &mut self,
        source: &traffic_value::Value,
        target: &traffic_value::Value,
        location: &JsonLocation,
        base: &Value,
        witness: &str,
        clocks: AnchorClocks,
        depth: usize,
    ) -> Result<()> {
        if depth > 32 || self.examined >= NODE_LIMIT {
            self.limit(if depth > 32 {
                "json_depth"
            } else {
                "json_nodes"
            });
            return Ok(());
        }
        if source == target {
            return Ok(());
        }
        self.examined += 1;
        let mut facts = base.clone();
        facts["clocks"] = clocks.observations();
        facts["settings"] = json!({"time":self.time});
        let findings = crate::value_extensions::analyze_values(
            &self.policies,
            source,
            target,
            &location.pointer,
            &facts,
        )?;
        let proposed = findings.iter().any(|finding| finding.proposal.is_some());
        for finding in findings {
            self.record_finding(&finding, base, witness)?;
            if let Some(proposal) = &finding.proposal {
                self.push(location, proposal, witness, &finding)?;
            }
        }
        if proposed {
            return Ok(());
        }
        if let (Some(source), Some(target)) = (source.as_object(), target.as_object()) {
            for (key, value) in source {
                if self.examined >= NODE_LIMIT {
                    self.limit("json_nodes");
                    break;
                }
                if key.contains('\0') {
                    continue;
                }
                if let Some(other) = target.get(key) {
                    self.collect(
                        value,
                        other,
                        &location.key(key),
                        base,
                        witness,
                        clocks,
                        depth + 1,
                    )?;
                }
            }
        } else if let (Some(source), Some(target)) = (source.as_array(), target.as_array())
            && source.len() == target.len()
        {
            for (index, (value, other)) in source.iter().zip(target).enumerate() {
                if self.examined >= NODE_LIMIT {
                    self.limit("json_nodes");
                    break;
                }
                self.collect(
                    value,
                    other,
                    &location.element(index),
                    base,
                    witness,
                    clocks,
                    depth + 1,
                )?;
            }
        }
        Ok(())
    }

    fn record_finding(
        &mut self,
        finding: &traffic_policy::Finding,
        location: &Value,
        witness: &str,
    ) -> Result<()> {
        let mut value = serde_json::to_value(finding)?;
        value["location"] = location.clone();
        value["witness_id"] = json!(witness);
        let identity = serde_json::to_string(&value)?;
        if self.finding_ids.insert(identity) && self.findings.len() < LIMIT {
            self.findings.push(value);
        }
        Ok(())
    }

    fn push(
        &mut self,
        location: &JsonLocation,
        proposal: &traffic_policy::Proposal,
        witness: &str,
        finding: &traffic_policy::Finding,
    ) -> Result<()> {
        let (identity, draft_policy) = match proposal {
            traffic_policy::Proposal::Field(contract) => {
                let contract = serde_json::to_value(contract)?;
                (
                    serde_json::to_string(&(&location.pattern, &contract))?,
                    json!({"format":"traffic-policy/v3","json":{"fields":{&location.pattern:contract}}}),
                )
            }
            traffic_policy::Proposal::Document(document) => {
                let document = serde_json::to_value(document)?;
                anyhow::ensure!(
                    document.is_object() && document["format"] == "traffic-policy/v3",
                    "registered proposal requires a complete policy fragment"
                );
                (serde_json::to_string(&("document", &document))?, document)
            }
        };
        let id = format!(
            "draft-{}",
            super::super::super::fingerprint::id(&[&identity]).trim_start_matches("fnv1a64:")
        );
        self.candidate_bindings
            .entry(id.clone())
            .or_default()
            .insert((witness.into(), location.pointer.clone()));
        if !self.seen.insert(identity)
            || self.seen.len() <= self.summary_offset
            || self.values.len() >= LIMIT
        {
            return Ok(());
        }
        let candidate = json!({"candidate_id":id,"witness_id":witness,"mechanism":finding.policy,
            "draft_policy":draft_policy,
            "section_update":"add",
            "source_proof_required":true,"plan_ready":false,
            "hint":finding.hint,"summary":finding.summary,"requirements":finding.requirements});
        self.values.push(candidate);
        Ok(())
    }

    pub(super) fn candidates(&self) -> Vec<Value> {
        self.values
            .iter()
            .cloned()
            .map(|mut candidate| {
                let bindings = &self.candidate_bindings
                    [candidate["candidate_id"].as_str().expect("draft identity")];
                candidate["location_count"] = json!(bindings.len());
                candidate["locations_omitted"] = json!(bindings.len().saturating_sub(LIMIT));
                candidate["locations"] = json!(
                    bindings
                        .iter()
                        .take(LIMIT)
                        .map(|(witness, pointer)| json!({"witness_id":witness,"pointer":pointer}))
                        .collect::<Vec<_>>()
                );
                candidate
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
