//! Pure, bounded value hypotheses. Evidence and selection remain with callers.
use super::json::{self, AnchorClocks, Comparison, Field};
use crate::policy::{CompiledJsonPolicy, FieldContract};
use serde_json::{Value, json};

pub use traffic_contract::hypothesis::Candidate;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct Considered {
    pub(crate) candidate: Candidate,
    pub(crate) passed: bool,
    pub(crate) reason: String,
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub(crate) struct Preview {
    pub(crate) comparison: Option<Comparison>,
    pub(crate) attempts: Vec<Considered>,
    pub(crate) complete: bool,
}

#[allow(dead_code)]
pub(crate) fn preview_json(
    case: &str,
    source: &[u8],
    target: &[u8],
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Preview {
    let (Some(source), Some(target)) = (
        crate::json_value::parse(source),
        crate::json_value::parse(target),
    ) else {
        return Preview {
            complete: true,
            ..Default::default()
        };
    };
    preview_values(case, &source, &target, plan, clocks)
}

#[allow(dead_code)]
pub(crate) fn preview_values(
    case: &str,
    source: &Value,
    target: &Value,
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Preview {
    let automatic = match plan.selected_fields_with_clocks(source, clocks) {
        Ok(fields) => fields
            .into_iter()
            .filter(|field| field.rule_id == super::time::automatic::RULE_ID)
            .map(|field| field.pointer)
            .collect::<Vec<_>>(),
        Err(_) => {
            return Preview {
                complete: false,
                ..Default::default()
            };
        }
    };
    let mut walk = Walk {
        case,
        clocks,
        selected: plan
            .fields
            .keys()
            .chain(automatic.iter())
            .map(String::as_str)
            .collect(),
        nodes: 0,
        complete: true,
        comparison: Default::default(),
        candidates: vec![],
        attempts: vec![],
    };
    let passed = walk.visit(source, target, "", "", 0);
    let comparison = (|| {
        if !passed || !walk.complete || walk.candidates.is_empty() {
            return None;
        }
        let verify = |context: json::LeafContext<'_>| {
            if context.source_pointer != context.target_pointer
                || source.pointer(context.source_pointer) != Some(context.source)
                || target.pointer(context.target_pointer) != Some(context.target)
            {
                return Err("hypothesis leaf observations changed".into());
            }
            Ok(json::LeafObservations::default())
        };
        let verified = walk
            .candidates
            .iter()
            .map(|candidate| json::VerifiedField {
                rule_id: "schema:diagnostic-hypothesis",
                pointer: &candidate.pointer,
                verifier: &verify,
            })
            .collect::<Vec<_>>();
        let mut result =
            super::global::compare_logical_with_verified(source, target, plan, clocks, &verified)
                .ok()?;
        result.evaluated.remove("schema:diagnostic-hypothesis");
        result.merge_and_validate(walk.comparison);
        if !result.passed() {
            return None;
        }
        result.pre_matches = walk.candidates;
        Some(result)
    })();
    Preview {
        comparison,
        attempts: walk.attempts,
        complete: walk.complete,
    }
}

#[allow(dead_code)]
struct Walk<'a> {
    case: &'a str,
    clocks: AnchorClocks,
    selected: Vec<&'a str>,
    nodes: usize,
    complete: bool,
    comparison: Comparison,
    candidates: Vec<Candidate>,
    attempts: Vec<Considered>,
}

impl Walk<'_> {
    #[allow(dead_code)]
    fn visit(
        &mut self,
        source: &Value,
        target: &Value,
        pointer: &str,
        pattern: &str,
        depth: usize,
    ) -> bool {
        self.nodes += 1;
        if depth > 32 || self.nodes > 4096 || self.attempts.len() >= 128 {
            self.complete = false;
            return false;
        }
        if source == target {
            return true;
        }
        if let (Some(a), Some(b)) = (source.as_object(), target.as_object()) {
            let mut passed = a.len() == b.len();
            for (key, value) in a {
                let Some(other) = b.get(key) else {
                    passed = false;
                    continue;
                };
                let key = key.replace('~', "~0").replace('/', "~1");
                passed &= self.visit(
                    value,
                    other,
                    &format!("{pointer}/{key}"),
                    &format!("{pattern}/{key}"),
                    depth + 1,
                );
            }
            return passed;
        }
        if let (Some(a), Some(b)) = (source.as_array(), target.as_array()) {
            let mut passed = a.len() == b.len();
            for (i, (a, b)) in a.iter().zip(b).enumerate() {
                passed &= self.visit(
                    a,
                    b,
                    &format!("{pointer}/{i}"),
                    &format!("{pattern}/*"),
                    depth + 1,
                );
            }
            return passed;
        }
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
        for (contract, draft) in leaf_hypotheses(source) {
            if self.attempts.len() >= 128 {
                self.complete = false;
                return false;
            }
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
            let passed = checked.passed();
            let draft =
                json!({"format":crate::policy::POLICY_FORMAT,"json":{"fields":{pattern:draft}}});
            let digest = crate::policy_evidence::digest(
                &serde_json::to_vec(&draft).expect("draft serializes"),
            );
            let candidate = Candidate {
                case_id: self.case.into(),
                candidate_id: format!("pre-match-{}", &digest[..16]),
                attempt_id: String::new(),
                pointer: pointer.into(),
                command: format!("json.fields:{pattern}"),
                draft_policy: draft,
                expected: signature(source),
                actual: signature(target),
                source_proof_required: true,
                reason: "rule_candidate_requires_source_proof".into(),
            };
            self.attempts.push(Considered {
                candidate: candidate.clone(),
                passed,
                reason: if passed {
                    "typed_value_hypothesis_validated".into()
                } else {
                    "typed_value_hypothesis_rejected".into()
                },
            });
            if passed {
                checked.evaluated.remove("pre_match");
                checked.time_validations.remove("pre_match");
                self.candidates.push(candidate);
                self.comparison.merge_and_validate(checked);
                return true;
            }
        }
        false
    }
}

#[allow(dead_code)]
pub(crate) fn signature(value: &Value) -> Value {
    json!({"presence":"present","signature":{"sha256":crate::policy_evidence::digest(&serde_json::to_vec(value).expect("value serializes"))}})
}

#[allow(dead_code)]
fn leaf_hypotheses(source: &Value) -> Vec<(Value, Value)> {
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
