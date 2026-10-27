//! Bounded rule hypotheses for diagnosis; callers retain dirty evidence until proof.
use super::json::{self, AnchorClocks, Comparison, Field};
use crate::policy::{CompiledJsonPolicy, FieldContract};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Candidate {
    pub(crate) case_id: String,
    pub(crate) candidate_id: String,
    pub(crate) pointer: String,
    pub(crate) command: String,
    pub(crate) draft_policy: Value,
    pub(crate) expected: Value,
    pub(crate) actual: Value,
    pub(crate) source_proof_required: bool,
    pub(crate) reason: String,
}

pub(crate) fn preview(
    case: &str,
    source: &[u8],
    target: &[u8],
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Option<Comparison> {
    let source = crate::json_value::parse(source)?;
    let mut target = crate::json_value::parse(target)?;
    let selected = plan.fields.keys().cloned().collect();
    let mut walk = Walk {
        case,
        clocks,
        selected,
        nodes: 0,
        comparison: Default::default(),
        candidates: vec![],
    };
    if !walk.visit(&source, &mut target, "", "", 0) || walk.candidates.is_empty() {
        return None;
    }
    let mut comparison = super::global::compare(
        &serde_json::to_vec(&source).ok()?,
        &serde_json::to_vec(&target).ok()?,
        plan,
        &[],
        clocks,
    )
    .ok()?;
    comparison.merge_and_validate(walk.comparison);
    if !comparison.passed() {
        return None;
    }
    comparison.pre_matches = walk.candidates;
    Some(comparison)
}

struct Walk<'a> {
    case: &'a str,
    clocks: AnchorClocks,
    selected: Vec<String>,
    nodes: usize,
    comparison: Comparison,
    candidates: Vec<Candidate>,
}

impl Walk<'_> {
    fn visit(
        &mut self,
        source: &Value,
        target: &mut Value,
        pointer: &str,
        pattern: &str,
        depth: usize,
    ) -> bool {
        self.nodes += 1;
        if depth > 32 || self.nodes > 4096 || self.candidates.len() >= 32 {
            return false;
        }
        if source == target {
            return true;
        }
        if let (Some(a), Some(b)) = (source.as_object(), target.as_object_mut()) {
            if a.len() != b.len() {
                return false;
            }
            for (key, value) in a {
                let Some(other) = b.get_mut(key) else {
                    return false;
                };
                let key = key.replace('~', "~0").replace('/', "~1");
                if !self.visit(
                    value,
                    other,
                    &format!("{pointer}/{key}"),
                    &format!("{pattern}/{key}"),
                    depth + 1,
                ) {
                    return false;
                }
            }
            return true;
        }
        if let (Some(a), Some(b)) = (source.as_array(), target.as_array_mut()) {
            if a.len() != b.len() {
                return false;
            }
            return a.iter().zip(b).enumerate().all(|(i, (a, b))| {
                self.visit(
                    a,
                    b,
                    &format!("{pointer}/{i}"),
                    &format!("{pattern}/*"),
                    depth + 1,
                )
            });
        }
        // Existing declarations retain their validation and applicability. A
        // hypothesis may explain an unowned leaf, never replace a failed rule.
        if self.selected.iter().any(|path| {
            let expected = path.split('/').collect::<Vec<_>>();
            let actual = pointer.split('/').collect::<Vec<_>>();
            expected.len() <= actual.len()
                && expected
                    .iter()
                    .zip(&actual)
                    .all(|(a, b)| *a == "*" || a == b)
        }) {
            return true;
        }
        for (contract, draft) in hypotheses(source) {
            let Ok(contract) = serde_json::from_value::<FieldContract>(contract) else {
                continue;
            };
            let mut checked = json::compare(
                source,
                target,
                &[Field {
                    rule_id: "pre_match",
                    pointer: "",
                    contract: &contract,
                }],
                self.clocks,
            );
            if !checked.passed() {
                continue;
            }
            checked.evaluated.remove("pre_match");
            checked.time_validations.remove("pre_match");
            let draft = json!({"format":"traffic-policy/v2","json":{"fields":{pattern:draft}}});
            let digest = crate::policy_evidence::digest(
                &serde_json::to_vec(&draft).expect("draft serializes"),
            );
            self.candidates.push(Candidate {
                case_id: self.case.into(), candidate_id: format!("pre-match-{}", &digest[..16]),
                pointer: pointer.into(), command: format!("json.fields:{pattern}"), draft_policy: draft,
                expected: json!({"presence":"present","signature":{"sha256":crate::policy_evidence::digest(&serde_json::to_vec(source).expect("value serializes"))}}),
                actual: json!({"presence":"present","signature":{"sha256":crate::policy_evidence::digest(&serde_json::to_vec(target).expect("value serializes"))}}),
                source_proof_required: true, reason: "rule_candidate_requires_source_proof".into(),
            });
            self.comparison.merge_and_validate(checked);
            *target = source.clone();
            return true;
        }
        false
    }
}

fn hypotheses(source: &Value) -> Vec<(Value, Value)> {
    if source
        .as_str()
        .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
    {
        return vec![(
            json!({"kind":"identity","format":"uuid"}),
            json!({"kind":"identity","formats":["uuid"]}),
        )];
    }
    let formats: &[&str] = match source.as_i64() {
        Some(946_684_800_000_000..) => &["unix_microseconds"],
        Some(946_684_800_000..) => &["unix_milliseconds"],
        Some(946_684_800..) => &["unix_seconds"],
        _ if source.is_string() => &["rfc3339", "sql_datetime", "iso8601_naive"],
        _ => &[],
    };
    formats
        .iter()
        .map(|f| {
            (
                json!({"kind":"time","format":f,"relation":"preserve_offset"}),
                json!({"kind":"time","formats":[f]}),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests;
