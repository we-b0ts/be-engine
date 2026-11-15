use super::*;

#[test]
fn source_http_session_requires_all_query_fields() {
    let generated = json!({"contract":{"kind":"uuid_v4"},"proof":proof()});
    let policy = compile(vec![
        json!({"id":"client","match":{"api":"POST /tasks","resource":{"protocol":"http","endpoint":"client.test:8080"},"operation":"GET","path":"/work"},"effect":{"kind":"http_request","query":{"first":generated,"second":generated}},"proof":proof()}),
    ]);
    let id = "01234567-89ab-4def-8123-456789abcdef";
    let event = json!({"event_type":"http_exchange","id":"source-http","scheme":"http","authority":"client.test:8080","method":"GET","uri":format!("/work?first={id}&second={id}"),"request_body":{"encoding":"utf8","data":"","truncated":false},"request_headers":{"x-request-time":["1970-01-01T00:16:40Z"]},"response_status":200,"response_headers":{},"response_body":{"encoding":"utf8","data":"ok","truncated":false},"timestamp":"1970-01-01T00:16:41Z","request_started_at":"1970-01-01T00:16:40Z","duration_ms":1000,"outcome":"response","error":null});
    assert!(check(&policy, std::slice::from_ref(&event)).unwrap().rules["client"] > 0);
    let mut missing = event.clone();
    missing["uri"] = json!(format!("/work?first={id}"));
    assert!(check(&policy, &[missing]).is_err());
}

#[test]
fn source_sql_session_validates_generated_uuid_formats_without_named_references() {
    let selector = json!({"api":"POST /tasks","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"operation":"COM_QUERY"});
    let mut capture = selector.clone();
    capture["sql"] = json!("INSERT INTO tasks(id) VALUES (?)");
    let mut reference = selector;
    reference["sql"] = json!("SELECT id FROM tasks WHERE id = ?");
    let field = |contract: Value| json!({"contract":contract,"proof":proof()});
    let policy = compile(vec![
        json!({"id":"sql-bind","match":capture,"effect":{"kind":"mysql_values","params":{"0":field(json!({"kind":"uuid_v4"}))}},"proof":proof()}),
        json!({"id":"sql-reference","match":reference,"effect":{"kind":"mysql_values","params":{"0":field(json!({"kind":"uuid_v4"}))}},"proof":proof()}),
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
    // The complete Source inventory still needs a witness for each selected rule.
    assert!(check(&policy, std::slice::from_ref(&use_id)).is_err());
    let wrong = event(
        "SELECT id FROM tasks WHERE id = 'fedcba98-7654-4321-8123-fedcba987654'",
        2,
    );
    assert!(check(&policy, &[bind, wrong]).is_ok());
}
