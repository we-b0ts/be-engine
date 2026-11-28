use crate::policy::*;
use serde_json::{Value, json};

fn value_rule() -> Value {
    json!({"id":"time","match":{"api":"GET /items"},
        "effect":{"kind":"response_generated","fields":{"/nonce":{"kind":"random","format":"hex","length":12}}},
        "proof":{"source":"items.py:1","fact":"Source generates a random nonce"}})
}

fn parse(rules: Vec<Value>) -> anyhow::Result<TrafficPolicy> {
    parse_policy(&json!({"format":"traffic-policy/v3","rules":rules}).to_string())
}

#[test]
fn source_lists_are_bounded_and_inherit_one_document_revision() {
    let mut rule = value_rule();
    rule["proof"]["source"] = json!(["items.py:1", "clock.py:2", "model.py:3"]);
    let input =
        json!({"format":"traffic-policy/v3","source_revision":"source-v1","rules":[rule.clone()]})
            .to_string();
    let parsed = parse_policy(&input).unwrap();
    let output = render_policy(&parsed).unwrap();
    assert_eq!(output.matches("source_revision:").count(), 1);
    assert!(!output.contains(" @ "));
    assert_eq!(
        super::references(&parsed.rules[0].proof().unwrap().source)
            .unwrap()
            .len(),
        3
    );
    assert!(parse_policy(&output).unwrap().rules[0].proof().is_none());
    assert_eq!(
        compile_policy(&parsed).unwrap().fingerprints,
        compile_policy(&parse_policy(&output).unwrap())
            .unwrap()
            .fingerprints
    );
    for source in [
        json!([]),
        json!(["a", "b", "c", "d"]),
        json!("a;b;c;d"),
        json!(["a;b", "c"]),
        json!(["a.py @ other-revision", "b.py"]),
    ] {
        rule["proof"]["source"] = source;
        assert!(parse(vec![rule.clone()]).is_err());
    }
}

#[test]
fn bounded_source_proof_is_retained_for_planning_and_excluded_from_runtime() {
    let fact = ["a".repeat(65), "b".repeat(65), "c".repeat(65)].join(" ");
    let mut rule = value_rule();
    rule["proof"]["fact"] = json!(fact);
    let policy = parse(vec![rule]).unwrap();
    assert_eq!(policy.rules[0].proof().unwrap().fact, fact);
    let output = render_policy(&policy).unwrap();
    assert!(!output.contains("proof:"));
    assert!(!output.contains("fact:"));
    assert_eq!(
        compile_policy(&parse_policy(&output).unwrap())
            .unwrap()
            .fingerprints,
        compile_policy(&policy).unwrap().fingerprints,
    );
}
