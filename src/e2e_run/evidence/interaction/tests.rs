use super::*;
use crate::e2e_run::result::{E2eValueObservation, E2eValuePresence};
use crate::interaction::model::WireMessage;

fn frame(sequence: u64, heartbeat: bool, data: Value) -> Value {
    json!({"sequence":sequence, "heartbeat":heartbeat, "offset_ms":0,
        "message":WireMessage::text(json!({"event":null,"id":null,"retry":null,"data":data.to_string()}).to_string())})
}

fn write_output(path: &Path, frames: Vec<Value>, target: bool, legacy: bool) -> Vec<u8> {
    let mut response = json!({"interaction":{"protocol":if legacy { "raw_stream" } else { "sse" }, "events":frames}});
    if target {
        response["version"] = json!(1);
    }
    crate::interaction::private::protect_output(&mut response, path).unwrap();
    // Reproduce the historical v1 SSE envelope without changing production writes.
    response["interaction"]["protocol"] = json!("sse");
    let bytes = serde_json::to_vec(&response).unwrap();
    std::fs::write(path, &bytes).unwrap();
    bytes
}

fn difference(pointer: &str) -> E2eCaseResponseDifference {
    let observation = || E2eValueObservation {
        presence: E2eValuePresence::Unavailable,
        value: None,
        jwt_candidate: false,
    };
    E2eCaseResponseDifference {
        pointer: pointer.into(),
        pointer_pattern: pointer.into(),
        difference_kind: crate::primary_protocol::assertion::ResponseDifferenceKind::ValueMismatch,
        unavailable_reason: None,
        expected: observation(),
        actual: observation(),
        interaction_diagnosis: None,
    }
}

#[test]
fn sse_page_reads_plaintext_and_legacy_encrypted_payloads_without_rewriting_evidence() {
    for legacy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join(".traffic-e2e/local/artifacts");
        std::fs::create_dir_all(&root).unwrap();
        crate::platform::encryption_key::load_or_create(temp.path()).unwrap();
        let expected = root.join("expected-response.json");
        let actual = root.join("actual-response.json");
        let source_bytes = write_output(
            &expected,
            vec![
                frame(0, true, json!({"heartbeat":"ping"})),
                frame(
                    1,
                    false,
                    json!({"type":"response.created", "response":{"id":"source-id", "optional":null}}),
                ),
                frame(2, false, json!({"type":"response.completed"})),
            ],
            false,
            legacy,
        );
        let target_bytes = write_output(
            &actual,
            vec![frame(
                0,
                false,
                json!({"type":"response.created", "response":{"id":"target-id", "access_token":"inspect-this-returned-value"}}),
            )],
            true,
            legacy,
        );
        assert_eq!(
            String::from_utf8_lossy(&target_bytes).contains("inspect-this-returned-value"),
            !legacy
        );
        let mut differences = vec![
            difference("$interaction/events/length"),
            difference("$interaction/events/0"),
            difference("$interaction/events/1"),
        ];
        diagnose_page(&mut differences, &expected, &actual);
        let inventory = differences[0].interaction_diagnosis.as_ref().unwrap();
        assert_eq!(inventory["expected"]["frames"].as_array().unwrap().len(), 2);
        assert_eq!(inventory["actual"]["frames"].as_array().unwrap().len(), 1);
        let frame = differences[1].interaction_diagnosis.as_ref().unwrap();
        assert_eq!(frame["expected"]["sequence"], 1);
        assert_eq!(frame["actual"]["sequence"], 0);
        assert_eq!(frame["expected"]["json_type"], "response.created");
        assert_eq!(
            frame["actual"]["data"]["response"]["access_token"],
            "inspect-this-returned-value"
        );
        let raw = frame["raw_json_differences"].as_array().unwrap();
        let id = raw.iter().find(|d| d["pointer"] == "/response/id").unwrap();
        assert_eq!(id["expected"]["value"], "source-id");
        assert_eq!(id["actual"]["value"], "target-id");
        let optional = raw
            .iter()
            .find(|d| d["pointer"] == "/response/optional")
            .unwrap();
        assert_eq!(optional["expected"]["presence"], "present");
        assert_eq!(optional["expected"]["value"], Value::Null);
        assert_eq!(optional["actual"]["presence"], "missing");
        let missing = differences[2].interaction_diagnosis.as_ref().unwrap();
        assert_eq!(missing["expected"]["json_type"], "response.completed");
        assert_eq!(missing["actual"]["presence"], "missing");
        assert_eq!(std::fs::read(&expected).unwrap(), source_bytes);
        assert_eq!(std::fs::read(&actual).unwrap(), target_bytes);

        // Historical ciphertext keeps its event-identity authentication contract.
        if legacy {
            let mut tampered: Value = serde_json::from_slice(&source_bytes).unwrap();
            tampered["interaction"]["events"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1);
            std::fs::write(&expected, tampered.to_string()).unwrap();
            diagnose_page(&mut differences, &expected, &actual);
            assert_eq!(
                differences[1].interaction_diagnosis.as_ref().unwrap()["expected"]["presence"],
                "unavailable"
            );
        }
    }
}

#[test]
fn diagnostic_limits_preserve_utf8_and_json_pointer_escaping() {
    let mut raw = RawDifferences::default();
    raw.compare("", Some(&json!({"a/b~c":null})), Some(&json!({})), 0);
    assert_eq!(raw.values[0]["pointer"], "/a~1b~0c");
    let source = json!((0..100).collect::<Vec<_>>());
    let target = json!((100..200).collect::<Vec<_>>());
    let mut raw = RawDifferences::default();
    raw.compare("", Some(&source), Some(&target), 0);
    assert_eq!(raw.values.len(), MAX_DIFFERENCES);
    assert!(raw.truncated);
    let value = bounded(&json!("中文".repeat(MAX_VALUE_BYTES)));
    assert_eq!(value["truncated"], true);
    assert!(value["preview"].as_str().unwrap().len() <= MAX_VALUE_BYTES);
}

#[test]
fn private_socketio_page_decodes_argument_roots_without_exposing_ciphertext_lengths_as_values() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join(".traffic-e2e/local/artifacts");
    std::fs::create_dir_all(&root).unwrap();
    crate::platform::encryption_key::load_or_create(temp.path()).unwrap();
    let source = root.join("expected-response.json");
    let target = root.join("actual-response.json");
    let write = |path: &Path, url: &str, target: bool| {
        let data = format!(
            "42/ns,1{}",
            json!(["capabilities",{"plugins":[{"url":url}],"optional":null}])
        );
        let mut value = json!({"interaction":{"protocol":"socket_io","events":[
            {"sequence":2,"heartbeat":false,"message":WireMessage::text(data)}
        ]}});
        if target {
            value["version"] = json!(1);
        }
        crate::interaction::private::protect_output(&mut value, path).unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(path, &bytes).unwrap();
        bytes
    };
    let before_source = write(&source, "source-private-url", false);
    let before_target = write(&target, "target-private-url", true);
    assert!(!String::from_utf8_lossy(&before_source).contains("source-private-url"));
    let mut rows = vec![difference(
        "$interaction/events/0/data/socketio/arguments/0/plugins/0/url",
    )];
    diagnose_page(&mut rows, &source, &target);
    let facts = rows[0].interaction_diagnosis.as_ref().unwrap();
    assert_eq!(facts["expected"]["event"], "capabilities");
    assert_eq!(facts["expected"]["representation"], "socketio_arguments");
    assert_eq!(
        facts["raw_json_differences"][0]["pointer"],
        "/0/plugins/0/url"
    );
    assert_eq!(
        facts["raw_json_differences"][0]["actual"]["value"],
        "target-private-url"
    );
    assert_eq!(std::fs::read(source).unwrap(), before_source);
    assert_eq!(std::fs::read(target).unwrap(), before_target);
}
