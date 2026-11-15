//! Later carriers may retain the exact typed times actually delivered by dependencies.
//! These private fingerprints do not grant a new time format or a clock fallback.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct DeliveredTimeCopies {
    pairs: Vec<ResponseTimeCopy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponseTimeCopy {
    source: [u8; 32],
    target: [u8; 32],
    deliveries: Vec<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
}

impl TimeCopyStore {
    pub(crate) fn delivered_copies(&self, case: &str) -> DeliveredTimeCopies {
        let pairs = self
            .cases
            .get(case)
            .into_iter()
            .flat_map(|case| &case.entries)
            .filter(|(_, value)| !value.deliveries.is_empty())
            .filter_map(|(key, value)| {
                Some(ResponseTimeCopy {
                    source: key.source,
                    target: value.target?,
                    deliveries: value
                        .deliveries
                        .iter()
                        .map(|delivery| delivery.clocks)
                        .collect(),
                })
            })
            .collect();
        DeliveredTimeCopies { pairs }
    }
}

impl DeliveredTimeCopies {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.pairs
                .iter()
                .map(|pair| pair.deliveries.len().max(1))
                .sum::<usize>()
                <= MAX_CASE_COPIES,
            "delivered time provenance exceeds its bound"
        );
        Ok(())
    }

    pub(crate) fn proofs(
        &self,
        source: &Value,
        plan: &crate::policy::CompiledJsonPolicy,
        clocks: super::super::json::AnchorClocks,
        observed: ClockPair,
    ) -> Result<Vec<VerifiedTimeCopy>> {
        self.validate()?;
        if self.pairs.is_empty() {
            return Ok(vec![]);
        }
        let Ok(observed) = observed.require() else {
            return Ok(vec![]);
        };
        let mut proofs = Vec::new();
        for leaf in global_leaves(source, plan, clocks)? {
            let source = time_hash(&leaf.value, &leaf.time)?;
            for pair in self.pairs.iter().filter(|pair| {
                pair.source == source
                    && pair
                        .deliveries
                        .iter()
                        .any(|&(a, b)| a <= observed.0 && b <= observed.1)
            }) {
                proofs.push(VerifiedTimeCopy {
                    rule_id: leaf.rule_id.into(),
                    source_pointer: leaf.pointer.clone(),
                    target_pattern: leaf.pattern.clone(),
                    source,
                    target: pair.target,
                    typed: true,
                });
                ensure!(
                    proofs.len() <= MAX_CASE_COPIES,
                    "delivered time proof expansion exceeds its bound"
                );
            }
        }
        Ok(proofs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(test)]
    use crate::policy::runtime::native_origin::TimeCopyPosition;
    use crate::value_contract::{global, json::AnchorClocks};
    use serde_json::json;

    fn fixture() -> (TimeCopyStore, crate::policy::CompiledPolicy, AnchorClocks) {
        let plan = crate::policy::parse_and_compile_policy(
            r#"format: traffic-policy/v3
json:
  fields:
    /block/timestamp: {kind: time, formats: [unix_milliseconds]}
    /response/blocks/*/timestamp: {kind: time, formats: [unix_milliseconds]}
    /response/created_at: {kind: time, formats: [unix_seconds]}
"#,
        )
        .unwrap();
        let clocks = AnchorClocks {
            dependency: ClockPair {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
            ..Default::default()
        };
        let time = plan.global_json.as_ref().unwrap().fields["/block/timestamp"]
            .select_contract_with_clock(&json!(1_010_000), clocks.dependency.source)
            .unwrap()
            .time()
            .unwrap();
        let position = TimeCopyPosition::Http {
            host: "dependency.test",
            port: 80,
            exchange: "recorded-call",
        };
        let read = TimeCopyRecord::new_time(
            &time,
            position,
            position,
            "/result/blocks/0/timestamp",
            "/result/blocks/0/timestamp",
            &json!(1_010_000),
            &json!(2_210_000),
        )
        .unwrap();
        let mut store = TimeCopyStore::default();
        store.set_record_clocks(ClockPair {
            source: chrono::DateTime::from_timestamp(1100, 0),
            target: chrono::DateTime::from_timestamp(2300, 0),
        });
        store.record_batch("case", vec![read]).unwrap();
        (store, plan, clocks)
    }

    fn compare(
        source: &Value,
        target: &Value,
        store: &TimeCopyStore,
        case: &str,
        plan: &crate::policy::CompiledPolicy,
        clocks: AnchorClocks,
    ) -> bool {
        let plan = plan.global_json.as_ref().unwrap();
        let proofs = store
            .delivered_copies(case)
            .proofs(
                source,
                plan,
                clocks,
                ClockPair {
                    source: chrono::DateTime::from_timestamp(1200, 0),
                    target: chrono::DateTime::from_timestamp(2400, 0),
                },
            )
            .unwrap();
        global::compare_logical_with_time_copies(source, target, plan, &[], clocks, &proofs)
            .unwrap()
            .passed()
    }

    #[test]
    fn delivered_dependency_times_survive_different_primary_and_dependency_starts() {
        let (store, plan, clocks) = fixture();
        for (source, target) in [
            (
                json!({"block":{"timestamp":1_010_000},"stable":7}),
                json!({"block":{"timestamp":2_210_000},"stable":7}),
            ),
            (
                json!({"response":{"blocks":[{"timestamp":1_010_000}],"created_at":1001}}),
                json!({"response":{"blocks":[{"timestamp":2_210_000}],"created_at":2001}}),
            ),
        ] {
            assert!(
                !global::compare_logical(
                    &source,
                    &target,
                    plan.global_json.as_ref().unwrap(),
                    &[],
                    clocks
                )
                .unwrap()
                .passed()
            );
            assert!(compare(&source, &target, &store, "case", &plan, clocks));
        }
    }

    #[test]
    fn copies_do_not_allow_retimestamping_content_changes_or_local_clock_changes() {
        let (store, plan, clocks) = fixture();
        let source =
            json!({"block":{"timestamp":1_010_000},"response":{"created_at":1001},"stable":7});
        for target in [
            json!({"block":{"timestamp":2_210_001},"response":{"created_at":2001},"stable":7}),
            json!({"block":{"timestamp":2_210_000},"response":{"created_at":2210},"stable":7}),
            json!({"block":{"timestamp":2_210_000},"response":{"created_at":2001},"stable":8}),
            json!({"block":{"timestamp":"2210000"},"response":{"created_at":2001},"stable":7}),
        ] {
            assert!(!compare(&source, &target, &store, "case", &plan, clocks));
        }
    }

    #[test]
    fn proofs_are_case_local_and_released_with_case_provenance() {
        let (mut store, plan, clocks) = fixture();
        let source = json!({"block":{"timestamp":1_010_000}});
        let target = json!({"block":{"timestamp":2_210_000}});
        assert!(!compare(
            &source,
            &target,
            &store,
            "another-case",
            &plan,
            clocks
        ));
        store.begin_case("case");
        assert!(!compare(&source, &target, &store, "case", &plan, clocks));
    }

    #[test]
    fn a_copy_must_have_arrived_before_this_frame_in_both_executions() {
        let (store, plan, clocks) = fixture();
        let plan = plan.global_json.as_ref().unwrap();
        let source = json!({"block":{"timestamp":1_010_000}});
        for (source_at, target_at) in [(1099, 2400), (1200, 2299)] {
            let observed = ClockPair {
                source: chrono::DateTime::from_timestamp(source_at, 0),
                target: chrono::DateTime::from_timestamp(target_at, 0),
            };
            assert!(
                store
                    .delivered_copies("case")
                    .proofs(&source, plan, clocks, observed)
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(
            store
                .delivered_copies("case")
                .proofs(&source, plan, clocks, ClockPair::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn builtin_copied_dates_follow_only_authorized_array_pairing() {
        let compiled = crate::policy::parse_and_compile_policy(
            "format: traffic-policy/v3\njson:\n  fields:\n    /items: {kind: unordered}\n",
        )
        .unwrap();
        let plan = compiled.global_json.as_ref().unwrap();
        let source = json!({"items":[{"id":1,"at":"2020-01-01T00:10:00Z"},{"id":2,"at":"fixed"}]});
        let target = json!({"items":[{"id":2,"at":"fixed"},{"id":1,"at":"2021-01-01T00:20:00Z"}]});
        let at = |text: &str| Some(text.parse().unwrap());
        let clocks = AnchorClocks::for_response(
            ClockPair::default(),
            ClockPair {
                source: at("2020-01-01T00:20:00Z"),
                target: at("2021-01-01T00:50:00Z"),
            },
        );
        let leaf = global_leaves(&source, plan, clocks).unwrap().remove(0);
        assert_eq!(leaf.pattern, "/items/*/at");
        assert_eq!(
            leaf.rule_id,
            crate::value_contract::time::automatic::RULE_ID
        );
        let position = TimeCopyPosition::Http {
            host: "dependency.test",
            port: 80,
            exchange: "read",
        };
        let record = TimeCopyRecord::new_time(
            &leaf.time,
            position,
            position,
            &leaf.pattern,
            &leaf.pattern,
            &source["items"][0]["at"],
            &target["items"][1]["at"],
        )
        .unwrap();
        let mut store = TimeCopyStore::default();
        store.set_record_clocks(ClockPair {
            source: at("2020-01-01T00:15:00Z"),
            target: at("2021-01-01T00:30:00Z"),
        });
        store.record_batch("case", vec![record]).unwrap();
        let copies = store
            .delivered_copies("case")
            .proofs(&source, plan, clocks, clocks.observation())
            .unwrap();
        assert!(
            !global::compare_logical(&source, &target, plan, &[], clocks)
                .unwrap()
                .passed()
        );
        assert!(
            global::compare_logical_with_time_copies(&source, &target, plan, &[], clocks, &copies)
                .unwrap()
                .passed()
        );
        let mut changed = target.clone();
        changed["items"][1]["at"] = json!("2021-01-01T00:20:01Z");
        assert!(
            !global::compare_logical_with_time_copies(
                &source,
                &changed,
                plan,
                &[],
                clocks,
                &copies
            )
            .unwrap()
            .passed()
        );
    }
}
