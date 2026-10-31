//! Structural JSON draft paths and bounded witness aggregation.
use super::*;

#[derive(Default)]
pub(super) struct JsonLocation {
    pointer: String,
    pattern: String,
}

impl JsonLocation {
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
    #[allow(clippy::too_many_arguments)] // One bounded walk retains immutable decoding and clock context.
    pub(super) fn collect(
        &mut self,
        source: &Value,
        target: &Value,
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
        if let (Some(source), Some(target)) = (source.as_array(), target.as_array()) {
            let sorted = |items: &[Value]| {
                let mut values = items.iter().map(Value::to_string).collect::<Vec<_>>();
                values.sort();
                values
            };
            if sorted(source) == sorted(target) {
                self.push(base, location, json!({"kind":"unordered"}), witness)?;
                return Ok(());
            }
        }
        let formats: &[&str] = if source.is_number() && target.is_number() {
            match source.as_i64().unwrap_or(0) {
                946_684_800_000_000.. => &["unix_microseconds"],
                946_684_800_000.. => &["unix_milliseconds"],
                946_684_800.. => &["unix_seconds"],
                _ => &[],
            }
        } else if source.is_string() && target.is_string() {
            &["rfc3339", "sql_datetime", "iso8601_naive"]
        } else {
            &[]
        };
        for format in formats {
            let contract = json!({"kind":"time","format":format,"relation":"preserve_offset"});
            let typed: FieldContract = serde_json::from_value(contract.clone())?;
            let observed = if base["surface"] == "api.response" {
                AnchorClocks {
                    dependency: clocks.case,
                    ..clocks
                }
            } else {
                clocks
            };
            if crate::value_contract::json::compare(
                source,
                target,
                &[Field {
                    rule_id: "draft",
                    pointer: "",
                    contract: &typed,
                }],
                observed,
            )
            .passed()
            {
                self.push(base, location, contract, witness)?;
                return Ok(());
            }
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

    fn push(
        &mut self,
        _base: &Value,
        location: &JsonLocation,
        contract: Value,
        witness: &str,
    ) -> Result<()> {
        let contract = if contract["kind"] == "time" {
            json!({"kind":"time","formats":[contract["format"]]})
        } else {
            contract
        };
        let identity = serde_json::to_string(&(&location.pattern, &contract))?;
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
        self.values.push(json!({"candidate_id":id,"witness_id":witness,"mechanism":contract["kind"],
            "draft_policy":{"format":"traffic-policy/v3","json":{"fields":{&location.pattern:contract}}},
            "section_update":"add",
            "source_proof_required":true,"plan_ready":false}));
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
