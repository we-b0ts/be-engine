//! Plan/apply uses the same explicit clock relationships as live Redis matching.
use super::*;
use crate::replay::policy::request_contract::tests::clock_groups::{actual, selector, source};

#[test]
fn grouped_clock_planning_preserves_witnesses_groups_and_fresh_replay_requirement() {
    for grouped in [false, true] {
        let mut fixture = Fixture::new();
        fixture.candidate("EVALSHA", &source(), &actual());
        fixture.events.push(exchange("EVALSHA", &source()));
        let plan = fixture.plan(selector(grouped));
        assert_eq!(plan.is_ok(), grouped);
        if let Ok(plan) = plan {
            let before = fs::read(fixture.case.join("dependencies.jsonl")).unwrap();
            assert!(plan.report().requires_fresh_replay);
            plan.apply().unwrap();
            assert_eq!(
                before,
                fs::read(fixture.case.join("dependencies.jsonl")).unwrap()
            );
            let loaded = crate::replay::policy::load_replay_policy(&fixture.policy).unwrap();
            let serialized = serde_json::to_value(&loaded.document.dependency_rules[0]).unwrap();
            assert_eq!(
                serialized["redis"]["commands"][0]["argument_values"]["17"]["clock_group"],
                "after_commit"
            );
            assert_eq!(
                serialized["redis"]["commands"][0]["argument_values"]["15"]["json"]["/changed_at_us"]
                    ["clock_group"],
                "event"
            );
        }
    }
}

#[test]
fn grouped_clock_planning_rejects_bad_copies_windows_business_fields_and_stale_source() {
    for (index, value) in [
        (14, "2000267684"),
        (17, "2005.316187"),
        (
            15,
            r#"{"changed_at_us":2000267683,"failed":true,"reason_id":""}"#,
        ),
    ] {
        let mut fixture = Fixture::new();
        let mut actual = actual();
        actual[index] = value;
        fixture.candidate("EVALSHA", &source(), &actual);
        fixture.events.push(exchange("EVALSHA", &source()));
        assert!(fixture.plan(selector(true)).is_err());
    }
    let mut fixture = Fixture::new();
    fixture.candidate("EVALSHA", &source(), &actual());
    fixture.events.push(exchange("EVALSHA", &source()));
    let plan = fixture.plan(selector(true)).unwrap();
    fs::write(fixture.case.join("dependencies.jsonl"), "changed").unwrap();
    assert!(plan.apply().is_err());
    assert!(
        crate::replay::policy::load_replay_policy(&fixture.policy)
            .unwrap()
            .document
            .dependency_rules
            .is_empty()
    );
}
