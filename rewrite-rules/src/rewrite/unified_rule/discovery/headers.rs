//! Header drafts describe one global name, independent of its carrier/API.
use super::*;
use crate::value_contract::http_headers::{self, HeaderSnapshot};

impl Drafts {
    pub fn headers(
        &mut self,
        source: &Value,
        target: Option<&Value>,
        witness: &str,
        clocks: AnchorClocks,
    ) -> Result<()> {
        let Ok(source) = serde_json::from_value::<HeaderSnapshot>(source.clone()) else {
            return Ok(());
        };
        let Ok(source) = http_headers::canonical(&source) else {
            return Ok(());
        };
        let target = target
            .and_then(|value| serde_json::from_value::<HeaderSnapshot>(value.clone()).ok())
            .and_then(|headers| http_headers::canonical(&headers).ok());
        for (name, values) in &source {
            if target.as_ref().and_then(|target| target.get(name)) == Some(values) {
                continue;
            }
            if self.examined >= NODE_LIMIT {
                self.limit("header_nodes");
                break;
            }
            self.examined += 1;
            let location = json!({"surface":"http.headers","name":name});
            self.add_entry(serde_json::to_string(&location)?,json!({
                "location":location,"witness_id":witness,"source_intent_required":true,
                "instruction":"Declare this header once under root http.headers using kind/formats. Header names are case-insensitive; presence, occurrence count and order stay strict. Equal Source identities join the same internal complete-value graph as JSON and storage. Independent clocks are required for changed times; Source observation alone grants no permission."
            }));
            let Some(actual) = target.as_ref().and_then(|target| target.get(name)) else {
                continue;
            };
            if values == actual {
                continue;
            }
            for format in [
                "amz_date",
                "rfc3339",
                "unix_seconds",
                "unix_milliseconds",
                "unix_microseconds",
            ] {
                let field: crate::policy::GlobalField =
                    serde_json::from_value(json!({"kind":"time","formats":[format]}))?;
                let policy = crate::policy::HttpPolicy {
                    headers: BTreeMap::from([(name.clone(), field)]),
                    ..Default::default()
                };
                let observed =
                    http_headers::compare(&source, target.as_ref().unwrap(), &policy, clocks)?;
                if !observed.passed() || observed.time_validations.values().all(|count| *count == 0)
                {
                    continue;
                }
                let identity = serde_json::to_string(&(name, format))?;
                let id = format!(
                    "draft-{}",
                    super::super::super::fingerprint::id(&[&identity])
                        .trim_start_matches("fnv1a64:")
                );
                self.candidate_bindings
                    .entry(id.clone())
                    .or_default()
                    .insert((witness.into(), name.clone()));
                if self.seen.insert(identity)
                    && self.seen.len() > self.summary_offset
                    && self.values.len() < LIMIT
                {
                    self.values.push(json!({"candidate_id":id,"witness_id":witness,"mechanism":"http_header_time",
                        "draft_policy":{"format":"traffic-policy/v3","http":{"headers":{name:{"kind":"time","formats":[format]}}}},
                        "section_update":"add",
                        "source_proof_required":true,"plan_ready":false}));
                }
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_header_draft_deduplicates_carriers_and_keeps_global_scope() {
        let mut drafts = Drafts::default();
        let source = json!({"X-Amz-Date":["20260101T000000Z"]});
        let target = json!({"x-amz-date":["20260101T000010Z"]});
        let clocks = AnchorClocks {
            dependency: crate::value_contract::time::ClockPair {
                source: Some("2026-01-01T00:00:00Z".parse().unwrap()),
                target: Some("2026-01-01T00:00:10Z".parse().unwrap()),
            },
            ..Default::default()
        };
        for witness in ["primary", "dependency"] {
            drafts
                .headers(&source, Some(&target), witness, clocks)
                .unwrap();
        }
        let candidates = drafts.candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0]["draft_policy"]["http"]["headers"]["x-amz-date"]["formats"],
            json!(["amz_date"])
        );
        assert_eq!(candidates[0]["location_count"], 2);
        assert_eq!(candidates[0]["section_update"], "add");
        assert!(candidates[0].get("preserve_existing_fields").is_none());
        assert!(candidates[0]["draft_policy"].get("rules").is_none());
        assert!(candidates[0]["draft_policy"].get("resources").is_none());
    }
}
