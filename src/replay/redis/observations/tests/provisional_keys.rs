//! A key hypothesis cannot choose another physical key's native state owner.
use super::*;
use crate::replay::redis::append::tests::state_with_policy;

#[test]
fn a_future_key_hypothesis_does_not_hide_the_established_expiry_owner() {
    let mut events = vec![
        event(
            1,
            "APPEND",
            &[b"content:text-1577836801000", b"zz"],
            b":2\r\n",
        ),
        event(
            2,
            "EXPIRE",
            &[b"content:text-1577836801000", b"60"],
            b":1\r\n",
        ),
        event(
            1,
            "RPUSH",
            &[b"blocks", br#"{"key":"content:text-1577836802000"}"#],
            b":1\r\n",
        ),
        event(
            2,
            "APPEND",
            &[b"content:text-1577836802000", b"ab"],
            b":2\r\n",
        ),
        event(
            3,
            "EXPIRE",
            &[b"content:text-1577836802000", b"60"],
            b":1\r\n",
        ),
    ];
    for e in &mut events[..2] {
        e["connection_id"] = json!(Uuid::from_u128(1));
    }
    let (_root, mut s) = state_with_policy(
        &events,
        json!({
            "format":"traffic-policy/v3", "json":{"fields":{
                "/key":{"kind":"identity","formats":[{"prefix":"content:text-","format":"decimal"}]}
            }}, "redis":{"keys":{"content:*":{"state":{"append":"concatenate","expire":"refresh"}}}}
        }),
    );
    s.request_contracts.configure_pre_match(true);
    let target_key = format!("content:text-{}", chrono::Utc::now().timestamp_millis());
    let metadata = format!(r#"{{"key":"{target_key}"}}"#);
    perform(&mut s, "RPUSH", &[b"blocks", metadata.as_bytes()]);
    perform(&mut s, "APPEND", &[target_key.as_bytes(), b"ab"]);
    let attempts_before = s.request_contracts.hypothesis_attempts().len();
    let refresh = request(&mut s, "EXPIRE", &[target_key.as_bytes(), b"60"])
        .expect("an uncreated key's hypothesis cannot reject the established key");
    assert_eq!(
        s.exchanges[refresh.index].args[0],
        b"content:text-1577836802000"
    );
    s.complete_exchange(&refresh);
    for _ in 0..8 {
        perform(&mut s, "EXPIRE", &[target_key.as_bytes(), b"60"]);
    }
    assert_eq!(
        s.request_contracts.hypothesis_attempts().len(),
        attempts_before,
        "native owner lookup must not grow diagnostic key hypotheses"
    );
    assert!(!s.exchanges[0].status.is_consumed());
    assert!(!s.exchanges[1].status.is_consumed());
    assert!(request(&mut s, "EXPIRE", &[target_key.as_bytes(), b"61"]).is_err());
    assert!(request(&mut s, "EXPIRE", &[b"content:text-1800000000010", b"60"]).is_err());
    perform(&mut s, "APPEND", &[b"content:text-1577836801000", b"zz"]);
    perform(&mut s, "EXPIRE", &[b"content:text-1577836801000", b"60"]);
    assert!(!s.case_is_dirty("case"));
}
