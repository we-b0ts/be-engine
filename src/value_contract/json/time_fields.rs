//! Compatible field declarations and contextual clocks share one checked leaf.
use super::*;

pub(super) fn compatible(left: &FieldContract, right: &FieldContract) -> bool {
    fn time(value: &FieldContract) -> Option<&FieldContract> {
        match value {
            FieldContract::Time { .. } => Some(value),
            FieldContract::Conditional { when, contract } if when.relative_pointer == "." => {
                time(contract)
            }
            _ => None,
        }
    }
    let (Some(left), Some(right)) = (time(left), time(right)) else {
        return false;
    };
    let (FieldContract::Time { .. }, FieldContract::Time { .. }) = (left, right) else {
        return false;
    };
    let (Some(mut left), Some(mut right)) = (left.time(), right.time()) else {
        return false;
    };
    left.clock_group = None;
    right.clock_group = None;
    left == right
}

impl Comparison {
    /// Independent physical values do not acquire relationships from sharing a
    /// declaration. Explicit Source clock groups retain their original scope.
    pub(crate) fn scope_schema_clocks(&mut self, occurrence: usize) {
        if self.relationships.is_empty() {
            return;
        }
        self.scope_schema_clocks_in(&format!("physical-value:{occurrence}"));
    }

    /// Nested decoded values keep their own occurrence while allowing outer
    /// carriers to add another scope. Hash contexts to keep physical pointers
    /// out of the private relationship keys as well as ordinary diagnostics.
    pub(crate) fn scope_schema_clocks_in(&mut self, context: &str) {
        use sha2::{Digest, Sha256};
        if self.relationships.is_empty() {
            return;
        }
        let context = Sha256::digest(context.as_bytes());
        self.relationships = std::mem::take(&mut self.relationships)
            .into_iter()
            .map(|((anchor, group, scope), pairs)| {
                let group = group.map(|group| {
                    if crate::policy::is_schema_clock_group(
                        group.split(".occurrence.").next().unwrap_or(&group),
                    ) {
                        format!("{group}.occurrence.{context:x}")
                    } else {
                        group
                    }
                });
                ((anchor, group, scope), pairs)
            })
            .collect();
    }
}

impl Comparator<'_> {
    #[allow(clippy::too_many_arguments)] // One leaf retains both physical pointers and its shared decisions.
    pub(super) fn time_field(
        &self,
        source: &Value,
        target: &Value,
        pointer: &str,
        target_pointer: &str,
        field: &Field<'_>,
        contract: &FieldContract,
        decisions: &mut Decisions,
    ) -> Result<(), Difference> {
        let FieldContract::Time {
            anchor,
            format,
            clock_group,
            ..
        } = contract
        else {
            return Err(difference(pointer, "expected a time field"));
        };
        let config = contract.time().expect("time contract");
        let copied = config.relation == TimeRelation::PreserveOffset
            && self
                .time_copies
                .get(&(field.rule_id, pointer))
                .into_iter()
                .flatten()
                .any(|proof| {
                    proof.permits(
                        field.rule_id,
                        pointer,
                        target_pointer,
                        source,
                        target,
                        &config,
                    )
                });
        let pair = if copied {
            parse_time_pair(source, target, &config)
        } else {
            compare_time(source, target, &config, self.clocks.get(*anchor))
        }
        .map_err(|error| difference(pointer, &error.to_string()))?;
        *decisions
            .time_validations
            .entry(field.rule_id.into())
            .or_default() += 1;
        if *format != TimestampFormat::CalendarDate {
            let scope = clock_scope::resolve(self, field, pointer, target_pointer, decisions)?;
            let key = (*anchor, clock_group.clone(), scope);
            if !decisions
                .times
                .get(&key)
                .is_some_and(|times| times.contains(&pair))
                && time_observation_count(
                    &decisions.times,
                    &key,
                    decisions.scoped_time_observations,
                ) >= MAX_TIME_OBSERVATIONS
            {
                return Err(difference(
                    pointer,
                    "time relationship exceeds 4096 distinct observations",
                ));
            }
            let scoped = !key.2.is_shared();
            let relationships = decisions.times.entry(key).or_default();
            if !relationships.contains(&pair) {
                for existing in relationships.iter() {
                    time::validate_relationships(&[*existing, pair])
                        .map_err(|error| difference(pointer, &error.to_string()))?;
                }
                relationships.push(pair);
                if scoped {
                    decisions.scoped_time_observations += 1;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn contract(group: &str) -> FieldContract {
        serde_json::from_value(json!({"kind":"time","format":"unix_seconds",
            "relation":"preserve_offset","clock_group":group}))
        .unwrap()
    }

    #[test]
    fn compatible_clocks_retain_both_rule_usage_and_contextual_relationships() {
        let global = contract("field-a");
        let contextual = contract("same-clock");
        let fields = [
            Field {
                rule_id: "global",
                pointer: "/a",
                contract: &global,
            },
            Field {
                rule_id: "context",
                pointer: "/a",
                contract: &contextual,
            },
            Field {
                rule_id: "context",
                pointer: "/b",
                contract: &contextual,
            },
        ];
        let clocks = AnchorClocks {
            dependency: time::ClockPair {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
            ..Default::default()
        };
        let source = json!({"a":1010,"b":1020});
        let result = compare(&source, &json!({"a":2010,"b":2020}), &fields, clocks);
        assert!(result.passed(), "{:?}", result.differences);
        assert_eq!(
            result.evaluated,
            BTreeSet::from(["global".into(), "context".into()])
        );
        assert!(!compare(&source, &json!({"a":2010,"b":2021}), &fields, clocks).passed());
        let incompatible = FieldContract::Unordered;
        let invalid = [
            fields[0],
            Field {
                rule_id: "invalid",
                pointer: "/a",
                contract: &incompatible,
            },
        ];
        assert!(!compare(&source, &source, &invalid, clocks).passed());
    }

    #[test]
    fn nested_schema_occurrences_keep_outer_carriers_and_explicit_groups_distinct() {
        let automatic = contract("schema.0123456789abcdef0123456789abcdef");
        let explicit = contract("source-clock");
        let fields = [
            Field {
                rule_id: "global",
                pointer: "/automatic",
                contract: &automatic,
            },
            Field {
                rule_id: "explicit",
                pointer: "/explicit",
                contract: &explicit,
            },
        ];
        let clocks = AnchorClocks {
            dependency: time::ClockPair {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
            ..Default::default()
        };
        let mut nested = compare(
            &json!({"automatic":1010,"explicit":1020}),
            &json!({"automatic":2010,"explicit":2020}),
            &fields,
            clocks,
        );
        assert!(nested.passed());
        nested.scope_schema_clocks_in("cipher:/user");
        let inner = nested.relationships.clone();
        nested.scope_schema_clocks(1);
        let mut other = Comparison {
            relationships: inner,
            ..Default::default()
        };
        other.scope_schema_clocks(2);
        let automatic_groups = |comparison: &Comparison| {
            comparison
                .relationships
                .keys()
                .filter_map(|(_, group, _)| group.clone())
                .filter(|group| group.starts_with("schema."))
                .collect::<Vec<_>>()
        };
        assert_ne!(automatic_groups(&nested), automatic_groups(&other));
        for comparison in [&nested, &other] {
            assert!(
                comparison
                    .relationships
                    .keys()
                    .any(|(_, group, _)| group.as_deref() == Some("source-clock")),
                "explicit Source clock groups must remain unchanged"
            );
        }
        let mut conflicting = compare(
            &json!({"automatic":1010,"explicit":1020}),
            &json!({"automatic":2011,"explicit":2021}),
            &fields,
            clocks,
        );
        assert!(conflicting.passed());
        conflicting.scope_schema_clocks_in("cipher:/user");
        conflicting.scope_schema_clocks(2);
        nested.merge_and_validate(conflicting);
        assert!(
            !nested.passed(),
            "explicit Source groups still relate independent carrier observations"
        );
    }
}

#[cfg(test)]
mod sentinel_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inactive_self_guard_dominates_contextual_time_permission() {
        let guarded:FieldContract=serde_json::from_value(json!({"kind":"conditional","when":{"relative_pointer":".","not_in":[0]},"contract":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"}})).unwrap();
        let context = guarded.unconditional().clone();
        let fields = [
            Field {
                rule_id: "field",
                pointer: "",
                contract: &guarded,
            },
            Field {
                rule_id: "context",
                pointer: "",
                contract: &context,
            },
        ];
        let clocks = AnchorClocks {
            dependency: time::ClockPair {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
            ..Default::default()
        };
        assert!(compare(&json!(0), &json!(0), &fields, clocks).passed());
        assert!(!compare(&json!(0), &json!(1000), &fields, clocks).passed());
        assert!(compare(&json!(1010), &json!(2010), &fields, clocks).passed());
    }
}
