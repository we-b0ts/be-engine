use super::super::tests::{event, request, rule, state};
use super::*;

fn cache(with_expiry: bool, fence: bool) -> (tempfile::TempDir, RedisReplayState) {
    let mut events = vec![
        event(1, "APPEND", &[b"content:1", b"abcd"], b":4\r\n"),
        event(2, "APPEND", &[b"content:1", b"ef"], b":6\r\n"),
    ];
    if with_expiry {
        events.insert(0, event(0, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"));
    }
    if fence {
        events.push(event(4, "GET", &[b"content:1"], b"$6\r\nabcdef\r\n"));
    }
    let (root, mut state) = state(&events, vec![rule()]);
    state
        .prepare_cancelled_caches("case", vec![b"abcdefgh".to_vec()])
        .unwrap();
    if with_expiry {
        let expiry = request(&mut state, "EXPIRE", &[b"content:1", b"60"]).unwrap();
        state.complete_exchange(&expiry);
    }
    (root, state)
}

#[test]
fn cancelled_cache_short_prefix_keeps_real_source_consumption_and_audits_missing_bytes() {
    let (_root, mut state) = cache(true, false);
    let matched = request(&mut state, "APPEND", &[b"content:1", b"ab"]).unwrap();
    state.complete_exchange(&matched);
    assert!(state.case_is_dirty("case"));
    state.confirm_cancelled_caches("other");
    assert!(state.case_is_dirty("case"));
    state.confirm_cancelled_caches("case");
    assert!(!state.case_is_dirty("case"));
    assert!(!state.snapshot().case_is_dirty("case"));
    assert!(
        state
            .exchanges
            .iter()
            .filter(|e| e.record.command == "APPEND")
            .all(|e| !e.status.is_consumed())
    );
    let audit = &state.cancelled_cache_audits()[0];
    assert_eq!(
        (
            audit.source_bytes,
            audit.target_bytes,
            audit.omitted_source_bytes
        ),
        (6, 2, 4)
    );
    assert_eq!(audit.partially_or_fully_omitted_source_exchanges, 2);
}

#[test]
fn cancelled_cache_longer_prefix_returns_actual_lengths_without_claiming_invented_source() {
    for split in [false, true] {
        let (_root, mut state) = cache(true, false);
        let first = if split {
            b"abcdef".as_slice()
        } else {
            b"abcdefgh".as_slice()
        };
        let matched = request(&mut state, "APPEND", &[b"content:1", first]).unwrap();
        state.complete_exchange(&matched);
        if split {
            let extra = request(&mut state, "APPEND", &[b"content:1", b"gh"]).unwrap();
            assert_eq!(extra.response, b":8\r\n");
            assert!(state.has_case_in_flight());
            state.complete_exchange(&extra);
        } else {
            assert_eq!(matched.response, b":8\r\n");
        }
        assert!(state.case_is_dirty("case"));
        assert!(state.snapshot().case_is_dirty("case"));
        state.confirm_cancelled_caches("case");
        assert!(!state.case_is_dirty("case"));
        assert!(!state.snapshot().case_is_dirty("case"));
        assert_eq!(state.exchanges.len(), 3);
        assert_eq!(state.cancelled_cache_audits()[0].additional_target_bytes, 2);
        let last = state.append_streams.audits.last().unwrap();
        assert_eq!(
            last.fragments.iter().map(|f| f.bytes).sum::<usize>(),
            if split { 0 } else { 6 }
        );
    }
}

#[test]
fn cache_allowance_never_accepts_wrong_bytes_gaps_or_content_after_the_primary_prefix() {
    for invalid in [b"abXdef".as_slice(), b"abdef", b"abcdefghi"] {
        let (_root, mut state) = cache(true, false);
        state.confirm_cancelled_caches("case");
        assert!(request(&mut state, "APPEND", &[b"content:1", invalid]).is_err());
        assert_eq!(state.append_streams.profiles[0].reserved, 0);
    }
}

#[test]
fn durable_or_observed_append_state_remains_strict_after_cancellation() {
    for (expiry, fence) in [(false, false), (true, true)] {
        let (_root, mut state) = cache(expiry, fence);
        let matched = request(&mut state, "APPEND", &[b"content:1", b"ab"]).unwrap();
        state.complete_exchange(&matched);
        state.confirm_cancelled_caches("case");
        assert!(state.case_is_dirty("case"));
        assert!(state.cancelled_cache_audits().is_empty());
    }
}

#[test]
fn failed_or_in_flight_cache_delivery_cannot_be_waived() {
    let (_root, mut state) = cache(true, false);
    let matched = request(&mut state, "APPEND", &[b"content:1", b"ab"]).unwrap();
    state.confirm_cancelled_caches("case");
    assert!(state.case_is_dirty("case"));
    assert!(state.cancelled_cache_audits().is_empty());
    state.fail_append(matched.append.as_ref().unwrap());
    assert!(state.case_is_dirty("case"));
    assert!(state.cancelled_cache_audits().is_empty());
}
