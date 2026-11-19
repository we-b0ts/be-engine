use super::*;
use crate::dependency_index::store;
use serde_json::json;
use std::io::Write;

fn event(uri: &str, data: &str) -> Value {
    json!({"event_type":"http_exchange","scheme":"http","authority":"issuer.test","method":"GET","uri":uri,
        "request_headers":{},"request_body":{"encoding":"utf8","data":"","truncated":false},
        "response_status":200,"response_headers":{},"response_body":{"encoding":"utf8","data":data,"truncated":false}})
}

#[test]
fn indexed_proof_reads_every_selected_record_and_no_unrelated_response_payload() {
    for global in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join(if global {
            "global-dependencies.jsonl"
        } else {
            "dependencies.jsonl"
        });
        let mut output = std::fs::File::create(&file).unwrap();
        let selected = format!("{}\n", event("/keys", "key-response"));
        for _ in 0..65 {
            output.write_all(selected.as_bytes()).unwrap();
        }
        for _ in 0..20 {
            writeln!(output, "{}", event("/noise", &"x".repeat(100_000))).unwrap();
        }
        drop(output);
        if global {
            super::super::global::load_global_index(&file, |_| Ok(())).unwrap();
        } else {
            super::super::load_file(&file).unwrap();
        }
        let mut count = 0;
        let read = visit(
            &file,
            |metadata| Ok(metadata["uri"] == "/keys"),
            |record| {
                assert_eq!(record["response_body"]["data"], "key-response");
                count += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(count, 65);
        assert_eq!(read, selected.len() as u64 * 65);
        assert!(read * 50 < std::fs::metadata(&file).unwrap().len());
    }
}

#[test]
fn selected_proof_cannot_use_a_corrupt_record_checksum() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("dependencies.jsonl");
    std::fs::write(&file, event("/keys", "key-response").to_string()).unwrap();
    let mut index = super::super::load_file(&file).unwrap();
    index.proof_records.as_mut().unwrap()[0].location.sha256 = "0".repeat(64);
    store::write_json(&temp.path().join(super::super::FRAGMENT), &index).unwrap();
    assert!(visit(&file, |_| Ok(true), |_| Ok(())).is_err());
}
