use super::*;

fn write_field(path: &Path, field: &str, observation: serde_json::Value) {
    let mut response: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    response[field] = observation;
    fs::write(path, serde_json::to_vec(&response).unwrap()).unwrap();
    if field == "interaction" && path.file_name().unwrap() == "expected-response.json" {
        let request_path = path.with_file_name("request.json");
        let mut request: serde_json::Value =
            serde_json::from_slice(&fs::read(&request_path).unwrap()).unwrap();
        request["interaction"] =
            serde_json::to_value(crate::interaction::model::InputTranscript::new(
                crate::interaction::model::Protocol::Sse,
                crate::interaction::policy::InteractionPolicy::default(),
            ))
            .unwrap();
        fs::write(request_path, serde_json::to_vec(&request).unwrap()).unwrap();
    }
}

fn observation(data: &str, clean: bool) -> serde_json::Value {
    let message = serde_json::to_string(&crate::interaction::stream::SseEvent {
        event: None,
        id: None,
        retry: None,
        data: data.into(),
    })
    .unwrap();
    json!({"version":1,"protocol":"sse", "events":[
        {"sequence":1,"offset_ms":20,"message":{"kind":"text","data":message},"heartbeat":false}
    ], "end":{"reason":"server_eof","offset_ms":100,"pending":[],"clean":clean}})
}

#[test]
fn legacy_fifty_ms_evidence_requires_rerecording_and_stays_immutable() {
    let (_temp, options) = write_raw_case("", "data: ready\n\n", "data: ready\n\n");
    write_field(
        &options.expected_response,
        "sse_observation",
        json!({"window_ms":50,"end":"observation_window_elapsed"}),
    );
    let before = fs::read(&options.expected_response).unwrap();
    let expected_path = options.expected_response.clone();
    let error = assert_recorded_response(options).err().unwrap();
    assert!(format!("{error:#}").contains("require re-recording"));
    assert_eq!(fs::read(expected_path).unwrap(), before);
}

#[test]
fn semantic_stream_events_and_closure_determine_compatibility() {
    for (actual, should_pass, pointer) in [
        (observation("source", true), true, ""),
        (
            observation("target", true),
            false,
            "$interaction/events/0/sse/data",
        ),
        (
            observation("source", false),
            false,
            "$interaction/end/clean",
        ),
        (serde_json::Value::Null, false, "$interaction"),
    ] {
        let (_temp, options) = write_raw_case("", "different transport chunks", "other chunks");
        write_field(
            &options.expected_response,
            "interaction",
            observation("source", true),
        );
        write_field(&options.actual_response, "interaction", actual);
        let report = assert_recorded_response(options).unwrap();
        assert_eq!(report.passed, should_pass);
        if !should_pass {
            assert!(
                report
                    .differences
                    .iter()
                    .any(|difference| difference.pointer == pointer)
            );
        }
    }
}

#[test]
fn matching_incomplete_source_and_target_never_pass() {
    let (_temp, options) = write_raw_case("", "", "");
    write_field(
        &options.expected_response,
        "interaction",
        observation("partial", false),
    );
    write_field(
        &options.actual_response,
        "interaction",
        observation("partial", false),
    );
    assert!(!assert_recorded_response(options).unwrap().passed);
}

#[test]
fn engine_client_and_server_closure_are_distinct_contracts() {
    for source in ["business_idle", "client_close", "server_eof"] {
        for target in ["business_idle", "client_close", "server_eof"] {
            let (_temp, options) = write_raw_case("", "", "");
            let mut expected = observation("same events", true);
            expected["end"]["reason"] = source.into();
            let mut actual = expected.clone();
            actual["end"]["reason"] = target.into();
            write_field(&options.expected_response, "interaction", expected);
            write_field(&options.actual_response, "interaction", actual);
            let report = assert_recorded_response(options).unwrap();
            assert_eq!(report.passed, source == target, "{source} versus {target}");
            if source != target {
                assert!(
                    report
                        .differences
                        .iter()
                        .any(|difference| { difference.pointer == "$interaction/end/reason" })
                );
            }
        }
    }
}

#[test]
fn websocket_close_code_and_reason_are_compared() {
    for close in [
        json!({"code":1001,"reason":"finished"}),
        json!({"code":1000,"reason":"different"}),
    ] {
        let (_temp, options) = write_raw_case("", "", "");
        let mut expected = observation("42[\"result\",1]", true);
        expected["protocol"] = "socket_io".into();
        expected["end"]["close"] = json!({"code":1000,"reason":"finished"});
        let mut actual = expected.clone();
        actual["end"]["close"] = close;
        write_field(&options.expected_response, "interaction", expected);
        write_field(
            &options.request,
            "interaction",
            serde_json::to_value(crate::interaction::model::InputTranscript::new(
                crate::interaction::model::Protocol::SocketIo,
                crate::InteractionPolicy::default(),
            ))
            .unwrap(),
        );
        write_field(&options.actual_response, "interaction", actual);
        let report = assert_recorded_response(options).unwrap();
        assert!(!report.passed);
        assert!(
            report
                .differences
                .iter()
                .any(|difference| { difference.pointer == "$interaction/end/close" })
        );
    }
}

#[test]
fn plaintext_and_legacy_encrypted_sse_outputs_compare_without_rewriting_private_inputs() {
    for legacy in [false, true] {
        let (temp, mut options) = write_raw_case("", "", "");
        write_field(
            &options.expected_response,
            "interaction",
            observation("private-output", true),
        );
        write_field(
            &options.actual_response,
            "interaction",
            observation("private-output", true),
        );
        let case = temp
            .path()
            .join(".traffic-e2e/local/artifacts/recordings/case");
        fs::create_dir_all(&case).unwrap();
        crate::platform::encryption_key::load_or_create(temp.path()).unwrap();
        for path in [
            &mut options.request,
            &mut options.expected_response,
            &mut options.actual_response,
        ] {
            let destination = case.join(path.file_name().unwrap());
            fs::rename(&*path, &destination).unwrap();
            *path = destination;
        }
        let mut request: serde_json::Value =
            serde_json::from_slice(&fs::read(&options.request).unwrap()).unwrap();
        request["uri"] = json!("/sse?token=private-query");
        crate::interaction::private::protect_request(&mut request, &options.request).unwrap();
        fs::write(&options.request, serde_json::to_vec(&request).unwrap()).unwrap();
        for path in [&options.expected_response, &options.actual_response] {
            let mut response: serde_json::Value =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            if legacy {
                response["interaction"]["protocol"] = json!("raw_stream");
            }
            crate::interaction::private::protect_output(&mut response, path).unwrap();
            response["interaction"]["protocol"] = json!("sse");
            fs::write(path, serde_json::to_vec(&response).unwrap()).unwrap();
        }
        let paths = [
            options.request.clone(),
            options.expected_response.clone(),
            options.actual_response.clone(),
        ];
        let before = paths.each_ref().map(|path| fs::read(path).unwrap());
        assert!(!String::from_utf8_lossy(&before[0]).contains("private-query"));
        assert_eq!(
            String::from_utf8_lossy(&before[1]).contains("private-output"),
            !legacy
        );
        assert!(assert_recorded_response(options).unwrap().passed);
        let after = paths.each_ref().map(|path| fs::read(path).unwrap());
        assert_eq!(before, after);
    }
}
