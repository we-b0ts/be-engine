use super::*;

fn write_observation(path: &Path, observation: serde_json::Value) {
    let mut response: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    response["sse_observation"] = observation;
    fs::write(path, serde_json::to_vec(&response).unwrap()).unwrap();
}

#[test]
fn empty_bodies_do_not_hide_target_ending_an_open_source_stream() {
    let (_temp, options) = write_raw_case("", "", "");
    write_observation(
        &options.expected_response,
        json!({"window_ms": 50, "end": "observation_window_elapsed"}),
    );
    write_observation(
        &options.actual_response,
        json!({"window_ms": 50, "end": "server_eof"}),
    );
    let report = assert_recorded_response(options).unwrap();
    assert!(!report.passed);
    assert_eq!(report.differences.len(), 1);
    assert_eq!(report.differences[0].pointer, "$sse_observation/end");
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::SseStreamEndMismatch
    );
}

#[test]
fn equal_open_or_ended_streams_pass_with_matching_bodies() {
    for end in ["observation_window_elapsed", "server_eof"] {
        let (_temp, options) = write_raw_case("", "data: ready\n\n", "data: ready\n\n");
        let observation = json!({"window_ms": 50, "end": end});
        write_observation(&options.expected_response, observation.clone());
        write_observation(&options.actual_response, observation);
        assert!(assert_recorded_response(options).unwrap().passed);
    }
}

#[test]
fn missing_observation_and_changed_window_fail_separately_from_body() {
    for actual in [
        serde_json::Value::Null,
        json!({"window_ms": 100, "end": "observation_window_elapsed"}),
    ] {
        let (_temp, options) = write_raw_case("", "", "");
        write_observation(
            &options.expected_response,
            json!({"window_ms": 50, "end": "observation_window_elapsed"}),
        );
        write_observation(&options.actual_response, actual);
        let report = assert_recorded_response(options).unwrap();
        assert!(!report.passed);
        assert_eq!(report.differences.len(), 1);
        assert_eq!(
            report.differences[0].kind,
            ResponseDifferenceKind::SseObservationMismatch
        );
    }
}

#[test]
fn body_differences_are_still_reported_independently() {
    let (_temp, options) = write_raw_case("", "data: source\n\n", "data: target\n\n");
    let observation = json!({"window_ms": 50, "end": "observation_window_elapsed"});
    write_observation(&options.expected_response, observation.clone());
    write_observation(&options.actual_response, observation);
    let report = assert_recorded_response(options).unwrap();
    assert!(!report.passed);
    assert_eq!(report.differences.len(), 1);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::ExactBodyMismatch
    );
}
