use super::*;
use serde_json::json;
mod lset;
mod protocols;
mod read_back;
mod recorded_generated;
mod recorded_skip;
mod recorded_tasks;

fn proof() -> Value {
    json!({"source":"source.rs:trace","fact":"The complete Source trace validates every selected relationship"})
}
fn compile(rules: Vec<Value>) -> CompiledPolicy {
    crate::policy::compile_policy(
        &serde_json::from_value(json!({"format":"traffic-policy/v3","rules":rules})).unwrap(),
    )
    .unwrap()
}
fn request() -> Value {
    json!({"method":"POST","uri":"/tasks","timestamp":"1970-01-01T00:16:40Z","headers":{},"body":{"encoding":"utf8","data":"","truncated":false}})
}
fn check(policy: &CompiledPolicy, events: &[Value]) -> Result<NativeSourceDependencyValidation> {
    let temp = tempfile::tempdir()?;
    let request = request();
    std::fs::write(temp.path().join("request.json"), request.to_string())?;
    validate_native_source_dependencies(
        policy,
        &policy
            .native
            .iter()
            .map(|rule| rule.rule.id.clone())
            .collect(),
        temp.path(),
        &[NativeSourceCase {
            id: "case",
            dir: temp.path(),
            request: &request,
            events,
        }],
    )
}
fn redis(command: &str, args: &[&str], sequence: u64) -> Value {
    json!({"event_type":"redis_exchange","timestamp":format!("1970-01-01T00:16:{:02}Z",40+sequence),"request_started_at":format!("1970-01-01T00:16:{:02}Z",40+sequence),"duration_ms":0,
    "connection_id":"01234567-89ab-4def-8123-456789abcdef","sequence":sequence,"target_host":"cache.test","target_port":6379,"database":0,"username":"writer","resp_version":2,
    "command":command,"args":args.iter().map(|data|json!({"encoding":"utf8","data":data,"truncated":false})).collect::<Vec<_>>(),
    "response_kind":"integer","response":{"encoding":"utf8","data":":1\r\n","truncated":false},"outcome":"response","replay_safe":true})
}
fn resource() -> Value {
    json!({"protocol":"redis","endpoint":"cache.test:6379","database":0,"username":"writer"})
}

#[test]
fn source_session_validates_independent_random_json_with_a_generated_session_key() {
    use base64::Engine as _;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([17; 32]);
    let definition = json!({"id":"create-session","match":{"api":"POST /tasks","resource":resource(),
        "key":{"kind":"affix","prefix":"sessions:"}},"effect":{"kind":"redis_sequence",
        "key":{"contract":{"kind":"capture","template":"sessions:{value}","format":{"kind":"uuid_v4"}},"proof":proof()},
        "commands":[{"operation":"SET","arguments":{"1":{"contract":{"kind":"json","fields":{
            "/poll_token":{"contract":{"kind":"random","format":"base64url","length":43},"proof":proof()},
            "/created_at":{"contract":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"},"proof":proof()}
        }},"proof":proof()}}}]},"proof":proof()});
    let policy = compile(vec![definition.clone()]);
    let data = json!({"poll_token":token,"created_at":1000,"status":"pending"}).to_string();
    let event = redis(
        "SET",
        &[
            "sessions:01234567-89ab-4def-8123-456789abcdef",
            &data,
            "EX",
            "300",
        ],
        1,
    );
    assert_eq!(
        check(&policy, std::slice::from_ref(&event)).unwrap().rules["create-session"],
        1
    );
    let mut bad = event;
    bad["args"][1]["data"] =
        json!(json!({"poll_token":"bad","created_at":1000,"status":"pending"}).to_string());
    assert!(check(&policy, &[bad]).is_err());
    for (field, value) in [
        ("format", json!("string")),
        ("length", json!(0)),
        ("length", json!(1025)),
    ] {
        let mut bad = definition.clone();
        bad["effect"]["commands"][0]["arguments"]["1"]["contract"]["fields"]["/poll_token"]["contract"]
            [field] = value;
        let document =
            serde_json::from_value(json!({"format":"traffic-policy/v3","rules":[bad]})).unwrap();
        assert!(crate::policy::compile_policy(&document).is_err());
    }
}

#[test]
fn source_session_requires_complete_sequence_and_preserves_original_clocks_and_lanes() {
    let time = json!({"contract":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"},"proof":proof()});
    let policy = compile(vec![
        json!({"id":"schedule","match":{"api":"POST /tasks","resource":resource(),"key":{"kind":"exact","value":"tasks"}},"effect":{"kind":"redis_sequence","commands":[{"operation":"ZADD","arguments":{"1":time}},{"operation":"ZREMRANGEBYSCORE","arguments":{"2":time}}]},"proof":proof()}),
    ]);
    let first = redis("ZADD", &["tasks", "1000.25", "member"], 1);
    let second = redis("ZREMRANGEBYSCORE", &["tasks", "-inf", "910.25"], 2);
    assert!(check(&policy, std::slice::from_ref(&first)).is_err());
    // JSONL completion order is not the command issue order.
    let result = check(&policy, &[second.clone(), first.clone()]).unwrap();
    assert_eq!(result.rules["schedule"], 2);
    assert!(result.key_witnesses.is_empty());
    let mut reversed_clock = second.clone();
    reversed_clock["timestamp"] = json!("1970-01-01T00:16:40Z");
    reversed_clock["request_started_at"] = json!("1970-01-01T00:16:40Z");
    assert!(check(&policy, &[first.clone(), reversed_clock]).is_err());
    let mut wrong_auth = second;
    wrong_auth["username"] = json!("reader");
    assert!(check(&policy, &[first, wrong_auth]).is_err());
}

#[test]
fn source_session_requires_each_identity_reference_after_a_valid_capture() {
    let reference = |endpoint: &str| json!({"contract":{"resource":{"protocol":"redis","endpoint":endpoint,"database":0,"username":"writer"}},"proof":proof()});
    let policy = compile(vec![
        json!({"id":"job-id","match":{"api":"POST /tasks","resource":resource(),"operation":"RPUSH","key":{"kind":"exact","value":"jobs"}},"effect":{"kind":"identity","value_type":"string","format":"uuid_v4","capture":{"kind":"redis_argument","index":1},"references":[reference("cache.test:6379"),reference("other.test:6380")]},"proof":proof()}),
    ]);
    let id = "01234567-89ab-4def-8123-456789abcdef";
    let capture = redis("RPUSH", &["jobs", id], 1);
    let local = redis("SET", &["current", id], 2);
    let mut other = redis("SET", &["current", id], 3);
    other["target_host"] = json!("other.test");
    other["target_port"] = json!(6380);
    assert!(check(&policy, &[capture.clone(), local.clone()]).is_err());
    assert_eq!(
        check(&policy, &[capture.clone(), local.clone(), other.clone()])
            .unwrap()
            .rules["job-id"],
        1
    );
    let mut unrelated = other;
    unrelated["args"][1]["data"] = json!("unrelated");
    assert!(check(&policy, &[capture.clone(), local.clone(), unrelated]).is_err());
    let mut early = local;
    early["timestamp"] = json!("1970-01-01T00:16:40Z");
    early["request_started_at"] = json!("1970-01-01T00:16:40Z");
    early["sequence"] = json!(0);
    assert!(check(&policy, &[early, capture]).is_err());
}

#[test]
fn source_input_session_binds_actual_startup_key_files_and_rejects_unverified_tokens() {
    let policy = compile(vec![
        json!({"id":"input-token","match":{"api":"POST /tasks"},"effect":{"kind":"input_jwt","location":{"kind":"bearer_header","name":"authorization"},"algorithm":"HS256","time":"preserve_relative","signing_key":{"kind":"target_env","name":"TOKEN_KEY"}},"proof":proof()}),
    ]);
    let temp = tempfile::tempdir().unwrap();
    let environment = temp.path().join(crate::repository::LOCAL_TARGET_ENV_PATH);
    std::fs::create_dir_all(environment.parent().unwrap()).unwrap();
    std::fs::write(&environment, "TOKEN_KEY=source-key\n").unwrap();
    let token = |key: &[u8]| {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &json!({"exp":1300,"iat":1000,"sub":"kept","roles":["reader"]}),
            &jsonwebtoken::EncodingKey::from_secret(key),
        )
        .unwrap()
    };
    let mut source = request();
    source["headers"] = json!({"authorization":[format!("Bearer {}",token(b"source-key"))]});
    std::fs::write(temp.path().join("request.json"), source.to_string()).unwrap();
    let validate = |source: &Value| {
        validate_native_source_dependencies(
            &policy,
            &BTreeSet::from(["input-token".into()]),
            temp.path(),
            &[NativeSourceCase {
                id: "case",
                dir: temp.path(),
                request: source,
                events: &[],
            }],
        )
    };
    let checked = validate(&source).unwrap();
    assert_eq!(checked.rules["input-token"], 1);
    assert!(
        checked
            .key_witnesses
            .iter()
            .any(|(path, _)| *path == environment)
    );
    source["headers"]["authorization"][0] = json!(format!("Bearer {}", token(b"other-key")));
    std::fs::write(temp.path().join("request.json"), source.to_string()).unwrap();
    assert!(validate(&source).is_err());
}
