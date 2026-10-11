//! Capture one Redis write value and correlate its later decoded references.
use super::*;

pub(in crate::replay) struct ArgumentNormalization {
    pub source: Vec<Vec<u8>>,
    pub actual: Vec<Vec<u8>>,
    pub decision: DynamicDecision,
}

impl DynamicValues {
    pub(in crate::replay) fn redis(
        &self,
        case: Option<&str>,
        target: &TargetKey,
        database: i64,
        command: &str,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<ArgumentNormalization>> {
        let case = case?;
        let rules = self.selected(case, target);
        if rules.is_empty() {
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
            return self
                .normalize_arguments(Some(case), target, source, actual)
                .map(|result| {
                    result.map(|(source, actual)| ArgumentNormalization {
                        source,
                        actual,
                        decision: DynamicDecision::default(),
                    })
                });
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
            let mut source = source.to_vec();
            let mut actual = actual.to_vec();
            for rule in captures {
                let DynamicValueCapture::Redis {
                    argument_index,
                    json_pointer,
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
                if rule.value_type == DynamicValueType::Integer {
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
                decision.pairs.push((rule.id.clone(), pair));
            }
            let pairs = self.pairs(case, target, &decision);
            ensure!(
                source.len() == actual.len(),
                "dynamic Redis argument counts differ"
            );
            Ok(ArgumentNormalization {
                source: source
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        if index == 0 {
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
                        if index == 0 {
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
