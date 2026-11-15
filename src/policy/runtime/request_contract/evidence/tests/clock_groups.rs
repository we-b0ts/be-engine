//! Clock relationships use the live owner's protected evidence verifier.
use super::*;
use crate::policy::runtime::request_contract::tests::clock_groups::{actual, selector, source};

#[test]
fn grouped_clock_evidence_requires_explicit_relationships() {
    for grouped in [false, true] {
        let mut fixture = Fixture::new();
        fixture.candidate("EVALSHA", &source(), &actual());
        fixture.events.push(exchange("EVALSHA", &source()));
        assert_eq!(fixture.verify(selector(grouped)).is_ok(), grouped);
    }
}

#[test]
fn grouped_clock_evidence_rejects_bad_copies_windows_business_fields_and_stale_source() {
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
        assert!(fixture.verify(selector(true)).is_err());
    }
    let mut fixture = Fixture::new();
    fixture.candidate("EVALSHA", &source(), &actual());
    fixture.events.push(exchange("EVALSHA", &source()));
    assert_eq!(fixture.verify(selector(true)).unwrap(), 1);
    fixture.events[0]["args"][3]["data"] = json!("changed Source argument");
    assert!(fixture.verify(selector(true)).is_err());
}
