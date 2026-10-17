//! UUID-only comparison copies for composition with typed PUBLISH time contracts.
//! All other JSON values remain visible to the request comparator; preview is pure.
use super::*;
use anyhow::{Context, ensure};

pub(in crate::replay) struct JsonContext<'a> {
    pub case_id: Option<&'a str>,
    pub host: &'a str,
    pub port: u16,
    pub database: i64,
    pub username: Option<&'a str>,
}
pub(in crate::replay) struct JsonComparison {
    pub source: Vec<Vec<u8>>,
    pub actual: Vec<Vec<u8>>,
    bindings: Vec<(BindingKey, Vec<u8>, String)>,
}
impl PublishRules {
    pub(in crate::replay) fn preview_json(
        &self,
        context: JsonContext<'_>,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<JsonComparison>> {
        let rules: Vec<_> = self
            .rules
            .iter()
            .filter(|r| {
                self.scope.native_rule_scope_matches(
                    &r.id,
                    context.case_id,
                    crate::policy::Protocol::Redis,
                    &super::super::TargetKey {
                        host: context.host.into(),
                        port: context.port,
                    },
                    Some(&crate::policy::Database::Index(context.database)),
                    context.username,
                ) && r.selector.host.eq_ignore_ascii_case(context.host)
                    && r.selector.port == context.port
                    && source
                        .first()
                        .is_some_and(|c| c == r.selector.channel.as_bytes())
            })
            .collect();
        if rules.is_empty() {
            return None;
        }
        Some((|| {
            ensure!(
                source.len() == 2 && actual.len() == 2 && source[0] == actual[0],
                "PUBLISH channel or argument count differs"
            );
            let canonical = |bytes: &[u8]| -> Result<Vec<u8>> {
                let json = crate::replay::json_order::parse(bytes)
                    .context("PUBLISH time composition requires complete unique-member JSON")?;
                Ok(serde_json::to_vec(&json)?)
            };
            let source_json = canonical(&source[1])?;
            let mut actual_json = canonical(&actual[1])?;
            let source_spans =
                spans(&source_json).context("invalid source PUBLISH UUID payload")?;
            let actual_spans =
                spans(&actual_json).context("invalid target PUBLISH UUID payload")?;
            ensure!(
                source_spans.len() == actual_spans.len(),
                "PUBLISH UUID count changed"
            );
            let mut comparison = JsonComparison {
                source: vec![source[0].clone(), source_json.clone()],
                actual: Vec::new(),
                bindings: Vec::new(),
            };
            let mut selected = std::collections::BTreeSet::new();
            for rule in rules {
                // Resolve configured positions on the original bytes. Canonical JSON
                // changes member order, so a UUID index must never be reinterpreted there.
                let original_uuid = |payload: &[u8]| -> Result<Vec<u8>> {
                    let position = rule
                        .selector
                        .position(payload)
                        .context("PUBLISH UUID selector is absent or ambiguous")?;
                    let spans = spans(payload).context("invalid PUBLISH UUID payload")?;
                    Ok(payload[spans[position].clone()].to_vec())
                };
                let source = original_uuid(&source[1])?;
                let target = original_uuid(&actual[1])?;
                ensure!(
                    source.len() == target.len(),
                    "PUBLISH UUID representation changed"
                );
                let unique_position =
                    |payload: &[u8], spans: &[Range<usize>], uuid: &[u8]| -> Result<usize> {
                        let mut matches = spans
                            .iter()
                            .enumerate()
                            .filter(|(_, span)| &payload[(*span).clone()] == uuid);
                        let index = matches
                            .next()
                            .context("selected PUBLISH UUID is absent in canonical JSON")?
                            .0;
                        ensure!(
                            matches.next().is_none(),
                            "selected PUBLISH UUID location is ambiguous in JSON"
                        );
                        Ok(index)
                    };
                let a = unique_position(&source_json, &source_spans, &source)?;
                let b = unique_position(&actual_json, &actual_spans, &target)?;
                ensure!(
                    a == b && selected.insert(a),
                    "PUBLISH UUID selectors overlap or changed JSON location"
                );
                let key = (
                    rule.id.clone(),
                    context.database,
                    context.username.map(str::to_owned),
                    source.clone(),
                );
                ensure!(
                    self.bindings.get(&key).is_none_or(|bound| bound == &target)
                        && !self.bindings.iter().any(|(other, bound)| other.0 == key.0
                            && other.1 == key.1
                            && other.2 == key.2
                            && other.3 != key.3
                            && bound == &target),
                    "PUBLISH UUID binding is inconsistent"
                );
                actual_json[actual_spans[b].clone()].copy_from_slice(&source);
                comparison.bindings.push((key, target, rule.id.clone()));
            }
            comparison.actual = vec![actual[0].clone(), actual_json];
            Ok(comparison)
        })())
    }
    pub(in crate::replay) fn commit_json(&mut self, comparison: JsonComparison) -> Vec<String> {
        comparison
            .bindings
            .into_iter()
            .map(|(key, target, id)| {
                self.bindings.insert(key, target);
                id
            })
            .collect()
    }
}
