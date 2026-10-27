//! A previously accepted JSON key identity also owns the APPEND byte cursor.
use super::tests::{event, request, state_with_policy};
use super::*;
use serde_json::json;

fn runtime() -> (tempfile::TempDir, RedisReplayState) {
    state_with_policy(
        &[
            event(
                1,
                "RPUSH",
                &[b"blocks:1", br#"{"_content_key":"content:source"}"#],
                b":1\r\n",
            ),
            event(2, "APPEND", &[b"content:source", b"ab"], b":2\r\n"),
            event(3, "APPEND", &[b"content:source", b"cdef"], b":6\r\n"),
            event(4, "GET", &[b"content:source"], b"$6\r\nabcdef\r\n"),
        ],
        policy(),
    )
}

fn policy() -> serde_json::Value {
    json!({"format":"traffic-policy/v2", "json":{"fields":{
        "/_content_key":{"kind":"identity","formats":[{"prefix":"content:","format":"string"}]}
    }}, "redis":{"keys":{"content:*":{"append_stream":true}}}})
}

fn accept_key(state: &mut RedisReplayState) {
    let metadata = request(
        state,
        "RPUSH",
        &[b"blocks:1", br#"{"_content_key":"content:target"}"#],
    )
    .unwrap();
    state.complete_exchange(&metadata);
}

#[test]
fn accepted_complete_key_identity_advances_the_same_stream_for_exact_and_rebatched_appends() {
    for chunks in [
        vec![b"ab".as_slice(), b"cdef"],
        vec![b"a".as_slice(), b"bcd", b"ef"],
    ] {
        let (_root, mut state) = runtime();
        accept_key(&mut state);
        let mut length = 0;
        for chunk in chunks {
            let matched = request(&mut state, "APPEND", &[b"content:target", chunk]).unwrap();
            length += chunk.len();
            assert_eq!(matched.response, format!(":{length}\r\n").as_bytes());
            state.complete_exchange(&matched);
        }
        let read = request(&mut state, "GET", &[b"content:target"]).unwrap();
        assert_eq!(read.response, b"$6\r\nabcdef\r\n");
        state.complete_exchange(&read);
        assert!(state.snapshot().unused_case.is_empty());
        assert_eq!(state.append_streams.profiles[0].reserved, 6);
        assert!(request(&mut state, "APPEND", &[b"content:target", b"x"]).is_err());
    }
}

#[test]
fn known_key_projection_never_creates_identity_or_waives_bytes_and_read_boundaries() {
    let (_root, mut state) = runtime();
    assert!(request(&mut state, "APPEND", &[b"content:target", b"ab"]).is_err());
    accept_key(&mut state);
    assert!(request(&mut state, "APPEND", &[b"content:other", b"ab"]).is_err());
    assert!(request(&mut state, "APPEND", &[b"content:target", b"aX"]).is_err());
    assert_eq!(state.append_streams.profiles[0].reserved, 0);
    let matched = request(&mut state, "APPEND", &[b"content:target", b"ab"]).unwrap();
    state.complete_exchange(&matched);
    assert!(request(&mut state, "GET", &[b"content:target"]).is_err());
    assert!(request(&mut state, "APPEND", &[b"content:source", b"cdef"]).is_err());
}

#[test]
fn an_unknown_stream_key_cannot_be_learned_from_a_changed_json_append_payload() {
    let source = br#"{"_content_key":"content:source"}"#;
    let response = format!(":{}\r\n", source.len());
    let (_root, mut state) = state_with_policy(
        &[event(
            1,
            "APPEND",
            &[b"content:source", source],
            response.as_bytes(),
        )],
        policy(),
    );
    assert!(
        request(
            &mut state,
            "APPEND",
            &[b"content:target", br#"{"_content_key":"content:target"}"#]
        )
        .is_err()
    );
    assert_eq!(state.append_streams.profiles[0].reserved, 0);
    assert_eq!(state.exchanges[0].status, ReplayExchangeStatus::Available);
    assert!(!state.request_contracts.has_identities("case"));
    let exact = request(&mut state, "APPEND", &[b"content:source", source]).unwrap();
    state.complete_exchange(&exact);
    assert!(state.snapshot().unused_case.is_empty());
}
