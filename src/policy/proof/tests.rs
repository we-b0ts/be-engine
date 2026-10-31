use crate::policy::*;
use serde_json::{Value, json};

fn value_rule() -> Value {
    json!({"id":"time","match":{"api":"GET /items"},
        "effect":{"kind":"response_generated","fields":{"/nonce":{"kind":"random","format":"hex","length":12}}},
        "proof":{"source":"items.py:1","fact":"Source generates a random nonce"}})
}

fn native_rule() -> Value {
    json!({"id":"time","match":{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},
        "operation":"COM_QUERY","sql":"UPDATE items SET stamp=? WHERE id=?"},
        "effect":{"kind":"mysql_values","values":{"0":{"relative_time":"unix_seconds"}}},
        "proof":{"source":"items.py:1","fact":"Source reads the current clock"}})
}

fn parse(rules: Vec<Value>) -> anyhow::Result<TrafficPolicy> {
    parse_policy(&json!({"format":"traffic-policy/v3","rules":rules}).to_string())
}

#[test]
fn proof_limits_use_utf8_bytes_in_value_native_and_inherited_contracts() {
    for mut rule in [value_rule(), native_rule()] {
        for (fact, allowed) in [
            ("a".repeat(200), true),
            ("a".repeat(201), false),
            ("时".repeat(66), true),
            ("时".repeat(67), false),
        ] {
            rule["proof"]["fact"] = json!(fact);
            assert_eq!(parse(vec![rule.clone()]).is_ok(), allowed);
        }
    }
    let mut rule = native_rule();
    rule["effect"]["values"]["0"]["proof"] = json!({"fact":"a".repeat(201)});
    assert!(parse(vec![rule]).is_err());
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
fn runtime_rules_omit_proofs_while_provided_plan_proofs_remain_validated() {
    let capture = json!({"id":"paths","match":{},"effect":{"kind":"capture_http","case_paths":["/items"]},
        "proof":{"fact":"Capture this route without granting comparison permission"}});
    let input =
        json!({"format":"traffic-policy/v3","source_revision":format!("sha256:{}", "1".repeat(64)),
        "rules":[value_rule(),capture]})
        .to_string();
    let parsed = parse_policy(&input).unwrap();
    let output = render_policy(&parsed).unwrap();
    let reparsed = parse_policy(&output).unwrap();
    let paths = reparsed
        .rules
        .iter()
        .find(|rule| rule.id() == "paths")
        .unwrap();
    assert!(paths.proof().is_none());
    assert_eq!(
        compile_policy(&parsed).unwrap().fingerprints,
        compile_policy(&reparsed).unwrap().fingerprints
    );
    let mut changed = reparsed.clone();
    let PolicyRule::Native(rule) = changed
        .rules
        .iter_mut()
        .find(|rule| rule.id() == "paths")
        .unwrap()
    else {
        panic!("recording scope must retain its native acquisition owner");
    };
    rule.proof = Some(Proof {
        source: String::new(),
        fact: "The same acquisition scope has a shorter explanation".into(),
    });
    assert_eq!(
        compile_policy(&changed).unwrap().fingerprints.capture,
        compile_policy(&reparsed).unwrap().fingerprints.capture
    );
    for mut rule in [value_rule(), native_rule()] {
        rule["proof"].as_object_mut().unwrap().remove("source");
        assert!(parse(vec![rule.clone()]).is_err());
        rule.as_object_mut().unwrap().remove("proof");
        assert!(parse(vec![rule]).is_ok());
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

#[test]
fn state_epoch_proof_text_is_metadata_but_permission_presence_is_semantic() {
    let mut rule = json!({"id":"current","match":{"api":"POST /tasks",
        "resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},
        "operation":"SET","key":{"kind":"affix","prefix":"current:"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
            "references":[{"resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0}}],
            "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1,
                "state_epochs":true,"proof":{"source":"session.py:10","fact":"Reads observe the current Case-owned SET/DEL state"}}]},
        "proof":{"source":"session.py:1","fact":"Source stores a generated block id and later reads the same key"}});
    let before = compile_policy(&parse(vec![rule.clone()]).unwrap()).unwrap();
    rule["effect"]["read_back"][0]["proof"] = json!({"source":["session.py:10", "buffer.py:20"],"fact":"Buffered scheduling varies read counts inside the same Case-owned value lifetime"});
    let changed = compile_policy(&parse(vec![rule.clone()]).unwrap()).unwrap();
    assert_eq!(before.fingerprints.runtime, changed.fingerprints.runtime);
    assert_eq!(before.fingerprints.full, changed.fingerprints.full);
    let shared = parse_policy(
        &json!({"format":"traffic-policy/v3","source_revision":"source-v1",
        "rules":[rule.clone()]})
        .to_string(),
    )
    .unwrap();
    let rendered = render_policy(&shared).unwrap();
    assert_eq!(rendered.matches("source_revision:").count(), 1);
    assert!(!rendered.contains(" @ "));
    let yaml: serde_yaml::Value = serde_yaml::from_str(&rendered).unwrap();
    assert_eq!(
        yaml["redis"]["rules"][0]["effect"]["read_back"][0]["state_epochs"].as_bool(),
        Some(true)
    );
    assert!(!rendered.contains("proof:"));
    rule["effect"]["read_back"][0]
        .as_object_mut()
        .unwrap()
        .remove("state_epochs");
    let finite = compile_policy(&parse(vec![rule]).unwrap()).unwrap();
    assert_ne!(before.fingerprints.runtime, finite.fingerprints.runtime);
}
