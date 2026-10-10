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
                source.first() == actual.first(),
                "dynamic Redis capture key changed"
            );
            let mut decision = DynamicDecision::default();
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
                    source: strings::capture(source_value, json_pointer.as_deref())?,
                    target: strings::capture(actual_value, json_pointer.as_deref())?,
                };
                self.check_pair(case, rule, &pair, &decision)?;
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
