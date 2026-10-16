//! Capture one Redis write value and correlate its later decoded references.
use super::*;

pub(in crate::replay) struct ArgumentNormalization {
    pub source: Vec<Vec<u8>>,
    pub actual: Vec<Vec<u8>>,
    pub decision: DynamicDecision,
}

impl DynamicDecision {
    pub(in crate::replay::policy) fn differs(&self, rule: &str) -> bool {
        self.pairs
            .iter()
            .any(|(id, pair)| id == rule && pair.source != pair.target)
    }
}

impl DynamicValues {
    pub(in crate::replay::policy) fn validate_report_decision(
        &self,
        case: &str,
        decision: &DynamicDecision,
        report: &serde_json::Value,
    ) -> Result<()> {
        for (id, pair) in &decision.pairs {
            let source = super::super::config::fingerprint(pair.source.as_bytes());
            let target = super::super::config::fingerprint(pair.target.as_bytes());
            for proof in report["replay_policy"]["dynamic_bindings"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|proof| proof["case_id"] == case && proof["rule_id"] == *id)
            {
                ensure!(
                    proof["source_fingerprint"] != source || proof["target_fingerprint"] == target,
                    "dynamic identity changed its previously proven target reference"
                );
                ensure!(
                    proof["target_fingerprint"] != target || proof["source_fingerprint"] == source,
                    "distinct dynamic identities collapsed into a previously proven target"
                );
            }
        }
        Ok(())
    }

    pub(in crate::replay) fn redis(
        &self,
        case: Option<&str>,
        target: &TargetKey,
        database: i64,
        command: &str,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<ArgumentNormalization>> {
        self.redis_with_identity(case, target, database, None, command, source, actual)
    }

    pub(in crate::replay) fn redis_with_identity(
        &self,
        case: Option<&str>,
        target: &TargetKey,
        database: i64,
        username: Option<&str>,
        command: &str,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<ArgumentNormalization>> {
        let case = case?;
        let database_identity = crate::policy::Database::Index(database);
        let scope = super::scopes::ResourceContext {
            protocol: crate::policy::Protocol::Redis,
            target,
            database: Some(&database_identity),
            username,
            operation: command,
        };
        let rules = self.selected_scoped(case, scope, true);
        if rules.is_empty() && self.selected_scoped(case, scope, false).is_empty() {
            return None;
        }
        let captures = rules
            .into_iter()
            .filter(|rule| {
                let DynamicValueCapture::Redis {
                    target: endpoint,
                    database: db,
                    command: cmd,
                    key,
                    ..
                } = &rule.capture
                else {
                    return false;
                };
                endpoint.matches(target)
                    && *db == database
                    && cmd == command
                    && source
                        .first()
                        .is_some_and(|value| value.len() <= 1024 && key.matches(value))
            })
            .collect::<Vec<_>>();
        if captures.is_empty() {
            let pairs = self.scoped_pairs(case, scope, &DynamicDecision::default());
            if !source
                .iter()
                .any(|value| strings::contains_identity(value, &pairs))
            {
                return None;
            }
            return Some((|| {
                ensure!(
                    source.len() == actual.len(),
                    "dynamic request argument count differs"
                );
                Ok(ArgumentNormalization {
                    source: source
                        .iter()
                        .map(|value| strings::normalize(value, &pairs, false))
                        .collect::<Result<_>>()?,
                    actual: actual
                        .iter()
                        .map(|value| strings::normalize(value, &pairs, true))
                        .collect::<Result<_>>()?,
                    decision: DynamicDecision::default(),
                })
            })());
        }
        Some((|| {
            ensure!(
                command != "RPUSH" || source.len() <= 129,
                "RPUSH dynamic capture supports at most 128 elements"
            );
            ensure!(
                source.first() == actual.first(),
                "dynamic Redis capture key changed"
            );
            let mut decision = DynamicDecision::default();
            let mut strict_arguments = std::collections::BTreeSet::new();
            let mut legacy_decision = DynamicDecision::default();
            let mut source = source.to_vec();
            let mut actual = actual.to_vec();
            for rule in captures {
                let DynamicValueCapture::Redis {
                    argument_index,
                    json_pointer,
                    references,
                    ..
                } = &rule.capture
                else {
                    continue;
                };
                let source_value = source
                    .get(*argument_index)
                    .ok_or_else(|| anyhow::anyhow!("source Redis capture argument is absent"))?;
                let actual_value = actual
                    .get(*argument_index)
                    .ok_or_else(|| anyhow::anyhow!("target Redis capture argument is absent"))?;
                let pair = IdentityPair {
                    source: capture(source_value, json_pointer.as_deref(), rule.value_type)?,
                    target: capture(actual_value, json_pointer.as_deref(), rule.value_type)?,
                };
                self.check_pair(case, rule, &pair, &decision)?;
                if references.is_some() {
                    let (left, right) = super::redis_json::project(
                        &rule.capture,
                        &source[0],
                        source_value,
                        actual_value,
                        &pair,
                    )?;
                    source[*argument_index] = left;
                    actual[*argument_index] = right;
                    strict_arguments.insert(*argument_index);
                } else if rule.value_type == DynamicValueType::Integer {
                    let pointer = json_pointer.as_deref().expect("validated integer pointer");
                    let source_json =
                        crate::replay::json_order::parse(source_value).expect("validated capture");
                    let mut actual_json =
                        crate::replay::json_order::parse(actual_value).expect("validated capture");
                    *actual_json.pointer_mut(pointer).expect("validated pointer") =
                        serde_json::from_str(&pair.source)?;
                    // Canonicalize only complete, explicitly selected JSON arguments.
                    source[*argument_index] = serde_json::to_vec(&source_json)?;
                    actual[*argument_index] = serde_json::to_vec(&actual_json)?;
                }
                if references.is_none() {
                    legacy_decision.pairs.push((rule.id.clone(), pair.clone()));
                }
                decision.pairs.push((rule.id.clone(), pair));
            }
            // A new strict capture owns only its declared JSON pointers. Its
            // pending identity must never normalize another argument or field.
            let pairs = self.scoped_pairs(case, scope, &legacy_decision);
            ensure!(
                source.len() == actual.len(),
                "dynamic Redis argument counts differ"
            );
            Ok(ArgumentNormalization {
                source: source
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        if index == 0 || strict_arguments.contains(&index) {
                            Ok(value.clone())
                        } else {
                            strings::normalize(value, &pairs, false)
                        }
                    })
                    .collect::<Result<_>>()?,
                actual: actual
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        if index == 0 || strict_arguments.contains(&index) {
                            Ok(value.clone())
                        } else {
                            strings::normalize(value, &pairs, true)
                        }
                    })
                    .collect::<Result<_>>()?,
                decision,
            })
        })())
    }
}

pub(super) fn capture(
    bytes: &[u8],
    pointer: Option<&str>,
    value_type: DynamicValueType,
) -> Result<String> {
    if value_type == DynamicValueType::Integer {
        super::http::capture(
            bytes,
            pointer.ok_or_else(|| anyhow::anyhow!("integer capture requires a JSON pointer"))?,
            value_type,
        )
    } else {
        strings::capture(bytes, pointer)
    }
}
