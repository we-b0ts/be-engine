use super::*;
use serde_json::json;

fn output() -> OutputObservation {
    serde_json::from_value(json!({
        "version":1,"protocol":"sse","events":[
            {"sequence":1,"offset_ms":10,"message":{"kind":"text","data":json!({"event":"delta","data":json!({"type":"delta","item_id":"a","delta":"ab"}).to_string()}).to_string()}},
            {"sequence":2,"offset_ms":20,"message":{"kind":"text","data":json!({"event":"delta","data":json!({"type":"delta","item_id":"b","delta":"wrong"}).to_string()}).to_string()}},
            {"sequence":3,"offset_ms":30,"message":{"kind":"text","data":json!({"event":"delta","data":json!({"type":"delta","item_id":"a","delta":"cd"}).to_string()}).to_string()}},
            {"sequence":4,"offset_ms":101,"message":{"kind":"text","data":json!({"event":"delta","data":json!({"type":"delta","item_id":"a","delta":"future"}).to_string()}).to_string()}}
        ],"end":{"reason":"client_close","offset_ms":100,"pending":[0],"clean":true}
    })).unwrap()
}

#[test]
fn cache_content_ceiling_uses_only_the_same_pre_close_lane() {
    let streams = candidates(&output(), 100).unwrap();
    assert!(streams.contains(&b"abcd".to_vec()));
    assert!(streams.contains(&b"wrong".to_vec()));
    assert!(!streams.iter().any(|s| s.windows(6).any(|s| s == b"future")));
    assert!(!streams.contains(&b"abwrongcd".to_vec()));
}

#[test]
fn completed_corrupt_or_mismatched_primary_output_never_grants_cache_allowance() {
    let original = output();
    for mutate in 0..5 {
        let mut output = original.clone();
        match mutate {
            0 => output.end.reason = EndReason::ServerEof,
            1 => output.end.clean = false,
            2 => output.end.pending.clear(),
            3 => output.protocol = Protocol::SocketIo,
            _ => output.end.offset_ms += 1,
        }
        assert!(candidates(&output, 100).unwrap().is_empty());
    }
}
