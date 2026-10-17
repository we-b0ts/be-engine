use super::*;

#[test]
fn source_http_session_requires_all_query_fields_and_header_clocks() {
    let generated = json!({"contract":{"kind":"uuid_v4"},"proof":proof()});
    let header = json!({"contract":{"format":"rfc3339","relation":"request_window","anchor":"dependency.request_start"},"proof":proof()});
    let policy = compile(vec![
        json!({"id":"client","match":{"api":"POST /tasks","resource":{"protocol":"http","endpoint":"client.test:8080"},"operation":"GET","path":"/work"},"effect":{"kind":"http_request","headers":{"x-request-time":header},"query":{"first":generated,"second":generated}},"proof":proof()}),
    ]);
    let id = "01234567-89ab-4def-8123-456789abcdef";
    let event = json!({"event_type":"http_exchange","id":"source-http","scheme":"http","authority":"client.test:8080","method":"GET","uri":format!("/work?first={id}&second={id}"),"request_body":{"encoding":"utf8","data":"","truncated":false},"request_headers":{"x-request-time":["1970-01-01T00:16:40Z"]},"response_status":200,"response_headers":{},"response_body":{"encoding":"utf8","data":"ok","truncated":false},"timestamp":"1970-01-01T00:16:41Z","request_started_at":"1970-01-01T00:16:40Z","duration_ms":1000,"outcome":"response","error":null});
    assert!(check(&policy, std::slice::from_ref(&event)).unwrap().rules["client"] > 0);
    let mut missing = event.clone();
    missing["uri"] = json!(format!("/work?first={id}"));
    assert!(check(&policy, &[missing]).is_err());
    let mut late = event.clone();
    late["request_headers"]["x-request-time"][0] = json!("1970-01-01T00:16:46Z");
    assert!(check(&policy, &[late]).is_err());
    let mut missing = event;
    missing["request_headers"] = json!({});
    assert!(check(&policy, &[missing]).is_err());
}

#[test]
fn source_sql_session_requires_each_physical_response_time_column_and_complete_rows() {
    let time = json!({"format":"sql_datetime","relation":"preserve_offset","anchor":"case.request_start","utc_offset":"+00:00"});
    let column =
        json!({"contract":{"time":time,"preserve_values":["0001-01-01 00:00:00"]},"proof":proof()});
    let policy = compile(vec![
        json!({"id":"sql-times","match":{"api":"POST /tasks","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},"operation":"COM_QUERY","sql":"SELECT created, updated FROM tasks WHERE id = ?"},"effect":{"kind":"mysql_values","response_time":{"created":column,"updated":column}},"proof":proof()}),
    ]);
    let metadata = |name: &str| json!({"name":name,"column":name,"table":"tasks","family":"datetime","sql_type":"datetime","nullable":true});
    let cell = |value: &str| json!({"kind":"string","value":value});
    let event = json!({"event_type":"mysql_exchange","timestamp":"1970-01-01T00:16:41Z","duration_ms":1000,"connection_id":"01234567-89ab-4def-8123-456789abcdef","query_sequence":1,"target_host":"db.test","target_port":3306,"database":"app","username":"writer","command":"COM_QUERY","sql":"SELECT created, updated FROM tasks WHERE id = 7","response":{"status":"resultset","columns":[metadata("created"),metadata("updated")],"rows":[[cell("2026-10-17 00:00:00.123456"),cell("2026-10-17 00:00:01.123456")]],"row_count":1,"rows_truncated":false},"parse_warnings":[],"outcome":"response"});
    assert_eq!(
        check(&policy, std::slice::from_ref(&event)).unwrap().rules["sql-times"],
        1
    );
    let mut absent = event.clone();
    absent["response"]["columns"].as_array_mut().unwrap().pop();
    absent["response"]["rows"][0].as_array_mut().unwrap().pop();
    assert!(check(&policy, &[absent]).is_err());
    for cell in [json!({"kind":"null"}), cell("0001-01-01 00:00:00")] {
        let mut missing = event.clone();
        missing["response"]["rows"][0][1] = cell;
        assert!(check(&policy, &[missing]).is_err());
    }
    let mut incomplete = event;
    incomplete["response"]["row_count"] = json!(2);
    assert!(check(&policy, &[incomplete]).is_err());
}

#[test]
fn source_sql_session_exercises_atomic_generated_parameter_bindings() {
    let selector = json!({"api":"POST /tasks","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"operation":"COM_QUERY"});
    let mut capture = selector.clone();
    capture["sql"] = json!("INSERT INTO tasks(id) VALUES (?)");
    let mut reference = selector;
    reference["sql"] = json!("SELECT id FROM tasks WHERE id = ?");
    let field = |contract: Value| json!({"contract":contract,"proof":proof()});
    let policy = compile(vec![
        json!({"id":"sql-bind","match":capture,"effect":{"kind":"mysql_values","params":{"0":field(json!({"kind":"uuid_v4","binding":"task"}))}},"proof":proof()}),
        json!({"id":"sql-reference","match":reference,"effect":{"kind":"mysql_values","params":{"0":field(json!({"kind":"reference","binding":"task"}))}},"proof":proof()}),
    ]);
    let event = |sql: &str, sequence: u64| json!({"event_type":"mysql_exchange","timestamp":format!("1970-01-01T00:16:{:02}Z",40+sequence),"duration_ms":0,"connection_id":"01234567-89ab-4def-8123-456789abcdef","query_sequence":sequence,"target_host":"db.test","target_port":3306,"database":"app","command":"COM_QUERY","sql":sql,"response":{"status":"ok"},"parse_warnings":[],"outcome":"response"});
    let bind = event(
        "INSERT INTO tasks(id) VALUES ('01234567-89ab-4def-8123-456789abcdef')",
        1,
    );
    let use_id = event(
        "SELECT id FROM tasks WHERE id = '01234567-89ab-4def-8123-456789abcdef'",
        2,
    );
    let checked = check(&policy, &[bind.clone(), use_id.clone()]).unwrap();
    assert_eq!(checked.rules["sql-bind"], 1);
    assert_eq!(checked.rules["sql-reference"], 1);
    assert!(check(&policy, std::slice::from_ref(&use_id)).is_err());
    let wrong = event(
        "SELECT id FROM tasks WHERE id = 'fedcba98-7654-4321-8123-fedcba987654'",
        2,
    );
    assert!(check(&policy, &[bind, wrong]).is_err());
}
