//! Query timestamps use the same typed time and relationship owner as bodies.
use super::*;
use crate::policy::native::GeneratedValue;
use crate::policy::{FieldContract, NativeEffect, TimestampFormat};
use crate::value_contract::json::{self, AnchorClocks, Field};

impl ReplayPolicyRuntime {
    pub(super) fn compare_native_query_times(
        &self,
        request_times: crate::primary_protocol::assertion::RequestTimes,
        rules: &[&ReplayDependencyRule],
        source: &BTreeMap<String, Vec<String>>,
        target: &BTreeMap<String, Vec<String>>,
        decision: &mut DependencyRuleDecision,
    ) -> Result<BTreeSet<(String, String)>, String> {
        let Some(compiled) = self.loaded.compiled.as_ref() else {
            return Ok(BTreeSet::new());
        };
        let mut fields = vec![];
        let mut left = serde_json::Map::new();
        let mut right = serde_json::Map::new();
        let mut selected = BTreeSet::new();
        for projected in rules {
            let Some(rule) = compiled
                .native
                .iter()
                .find(|rule| rule.rule.id == projected.id)
            else {
                return Err("native HTTP rule lost its compiled contract".into());
            };
            let NativeEffect::HttpRequest(effect) = &rule.rule.effect else {
                continue;
            };
            for (name, value) in &effect.query {
                let GeneratedValue::Time(time) = &value.contract else {
                    continue;
                };
                let read = |values: &BTreeMap<String, Vec<String>>| -> Result<Value, String> {
                    let values = values
                        .get(name)
                        .ok_or_else(|| "selected query time is absent".to_string())?;
                    if values.len() != 1 {
                        return Err("selected query time must occur once".into());
                    }
                    match time.format {
                        TimestampFormat::UnixSeconds
                        | TimestampFormat::UnixMilliseconds
                        | TimestampFormat::UnixMicroseconds => {
                            crate::json_value::parse(values[0].as_bytes())
                                .filter(Value::is_number)
                                .ok_or_else(|| {
                                    "query time requires an unambiguous numeric value".into()
                                })
                        }
                        _ => Ok(Value::String(values[0].clone())),
                    }
                };
                left.insert(name.clone(), read(source)?);
                right.insert(name.clone(), read(target)?);
                fields.push((
                    rule.rule.id.clone(),
                    format!("/{}", name.replace('~', "~0").replace('/', "~1")),
                    FieldContract::Time {
                        format: time.format,
                        relation: time.relation,
                        anchor: time.anchor,
                        utc_offset: time.utc_offset.clone(),
                        clock_group: time.clock_group.clone(),
                        clock_scope: time.clock_scope.clone(),
                    },
                ));
                selected.insert((rule.rule.id.clone(), name.clone()));
            }
        }
        if fields.is_empty() {
            return Ok(selected);
        }
        let selected_fields = fields
            .iter()
            .map(|(id, pointer, contract)| Field {
                rule_id: id,
                pointer,
                contract,
            })
            .collect::<Vec<_>>();
        let comparison = json::compare(
            &Value::Object(left),
            &Value::Object(right),
            &selected_fields,
            AnchorClocks {
                dependency: request_times,
                ..Default::default()
            },
        );
        if !comparison.passed() {
            return Err(format!(
                "query time contract failed: {:?}",
                comparison.differences
            ));
        }
        for (id, count) in comparison.time_validations {
            decision.usage.entry(id).or_default().time_validations += count;
        }
        Ok(selected)
    }
}
