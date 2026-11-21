use super::*;
use serde_json::json;

#[derive(Clone, Debug, Default)]
struct SelectedRules;

impl CopyRuleScope for SelectedRules {
    fn permits(rule: &str) -> bool {
        rule == "registered.fixture"
    }
}

#[derive(Clone, Copy)]
struct Position;

impl PhysicalOrigin for Position {
    fn fingerprint(self) -> [u8; 32] {
        [7; 32]
    }
}

fn time() -> TimeContract {
    serde_json::from_value(json!({"format":"unix_seconds","relation":"preserve_offset"})).unwrap()
}

fn clocks(seconds: i64) -> ClockPair {
    let at = chrono::DateTime::from_timestamp(seconds, 0);
    ClockPair {
        source: at,
        target: at,
    }
}

fn recorded() -> TimeCopyStore<SelectedRules> {
    let mut store = TimeCopyStore::default();
    store.set_record_clocks(clocks(10));
    store
        .record_batch(
            "case",
            vec![
                TimeCopyRecord::new_time(
                    &time(),
                    Position,
                    Position,
                    "/at",
                    "/at",
                    &json!(1000),
                    &json!(2000),
                )
                .unwrap(),
            ],
        )
        .unwrap();
    store.set_lookup_clocks(clocks(20));
    store
}

#[test]
fn injected_scope_authorizes_custom_rule_identities() {
    let store = recorded();
    let lookup = |rule| {
        TimeCopyLookup::<SelectedRules>::new_time(
            &time(),
            Position,
            Position,
            "/at",
            "/at",
            &json!(1000),
            rule,
        )
    };
    assert!(lookup("another.rule").is_none());
    let proof = store
        .proof_prepared("case", &lookup("registered.fixture").unwrap())
        .unwrap();
    assert!(proof.permits_value(
        "registered.fixture",
        "/at",
        "/at",
        &json!(1000),
        &json!(2000),
        &time(),
    ));
    assert!(!proof.permits_value(
        "another.rule",
        "/at",
        "/at",
        &json!(1000),
        &json!(2000),
        &time(),
    ));
    assert!(
        store
            .proof_prepared("another.case", &lookup("registered.fixture").unwrap())
            .is_none()
    );
}

#[test]
fn absent_provenance_or_clocks_skip_field_projection() {
    let empty = DeliveredTimeCopies::<SelectedRules>::default();
    assert!(
        empty
            .proofs_with(
                || panic!("empty provenance cannot request fields"),
                clocks(20)
            )
            .unwrap()
            .is_empty()
    );
    let delivered = recorded().delivered_copies("case");
    assert!(
        delivered
            .proofs_with(
                || panic!("missing clocks cannot request fields"),
                ClockPair::default()
            )
            .unwrap()
            .is_empty()
    );
}

#[test]
fn exported_provenance_retains_its_serialized_contract() {
    let delivered = recorded().delivered_copies("case");
    let value = serde_json::to_value(&delivered).unwrap();
    assert_eq!(
        value.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["pairs"]
    );
    let restored: DeliveredTimeCopies<SelectedRules> = serde_json::from_value(value).unwrap();
    let proofs = restored
        .proofs_with(
            || {
                Ok(vec![TimeCopyLeaf {
                    rule_id: "registered.fixture",
                    pattern: "/copied/*/at".into(),
                    pointer: "/copied/0/at".into(),
                    value: json!(1000),
                    time: time(),
                }])
            },
            clocks(20),
        )
        .unwrap();
    assert_eq!(proofs.len(), 1);
    assert!(proofs[0].permits_value(
        "registered.fixture",
        "/copied/0/at",
        "/copied/9/at",
        &json!(1000),
        &json!(2000),
        &time(),
    ));
}
