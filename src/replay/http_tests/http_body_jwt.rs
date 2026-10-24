//! Signed outbound JSON fields preserve claims and finite HTTP delivery.
use super::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;

const KEY: &str = "synthetic-http-body-signing-key";
const SOURCE: i64 = 1_700_000_000;
const HOST: &str = "api.example.test";
const URI: &str = "/chat?mode=stable";
const RULE: &str = "chat-generated-fields";

fn token(claims: Value, algorithm: Algorithm, key: &str) -> String {
    encode(
        &Header::new(algorithm),
        &claims,
        &EncodingKey::from_secret(key.as_bytes()),
    )
    .unwrap()
}

fn claims(now: i64, skill: bool) -> Value {
    if skill {
        json!({"sub":"user-17","skill_id":"skill-8","iat":now,"exp":now+7200})
    } else {
        json!({"sub":"user-17","roles":["reader"],"exp":now+3600})
    }
}

fn body(now: i64, request_id: &str) -> Value {
    json!({
        "model":"stable-model", "messages":[{"role":"user","content":"synthetic input"}],
        "metadata":{
            "request_id":request_id,
            "auth_token":token(claims(now, false), Algorithm::HS256, KEY),
            "skill_identity_token":token(claims(now, true), Algorithm::HS256, KEY),
            "business_id":17
        }
    })
}

fn rule() -> Value {
    let jwt = json!({"kind":"jwt","algorithm":"HS256",
        "signing_key":{"kind":"target_env","name":"SECRET_KEY"}});
    json!({
        "id":RULE,
        "match":{"api":"POST /scenario","resource":{"protocol":"http","endpoint":"api.example.test:80"},
            "operation":"POST","path":"/chat"},
        "effect":{"kind":"http_request","json":{
            "/metadata/request_id":{"kind":"random","format":"hex","length":8},
            "/metadata/auth_token":jwt,
            "/metadata/skill_identity_token":jwt
        }},
        "proof":{"source":"synthetic/chat.rs:issue","fact":"Source generates an eight-character hex request ID and signs both identity tokens using its startup key"}
    })
}

struct Fixture {
    _temp: crate::replay::policy::test_fixture::ManagedFixtureDirectory,
    root: PathBuf,
    case: PathBuf,
    policy: PathBuf,
    original: Vec<u8>,
}

impl Fixture {
    async fn new(extra_rules: Vec<Value>, source: Value) -> Self {
        let temp = tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let local = root.join(".traffic-e2e/local");
        std::fs::create_dir_all(&local).unwrap();
        // The original request evidence uses the same managed encryption boundary
        // as production. Signing material remains a separate private startup input.
        let key_path = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        std::fs::write(
            key_path,
            crate::request_headers::generate_encryption_key().unwrap(),
        )
        .unwrap();
        std::fs::write(local.join("target.env"), format!("SECRET_KEY={KEY}\n")).unwrap();
        let case = local.join("recordings/run/case");
        write_http_case(
            &case,
            "http",
            HOST,
            URI,
            &source.to_string(),
            "recorded-result",
        )
        .await;
        let dependencies = case.join("dependencies.jsonl");
        let mut event: Value =
            serde_json::from_slice(&std::fs::read(&dependencies).unwrap()).unwrap();
        event["request_started_at"] = json!("2023-11-14T22:13:20Z");
        event["timestamp"] = json!("2023-11-14T22:13:20Z");
        event["request_headers"] = json!({"content-type":["application/json"]});
        let original = format!("{event}\n").into_bytes();
        std::fs::write(&dependencies, &original).unwrap();
        // A distant inbound clock proves that JWTs use the outbound dependency clock.
        std::fs::write(
            case.join("request.json"),
            r#"{"method":"POST","uri":"/scenario","timestamp":"2023-11-14T21:13:20Z"}"#,
        )
        .unwrap();
        std::fs::write(case.join("expected-response.json"), "{}").unwrap();
        let policy = root.join(".traffic-e2e/policy.yaml");
        let mut rules = vec![rule()];
        rules.extend(extra_rules);
        crate::replay::write_policy_fixture(
            &policy,
            json!({"format":"traffic-policy/v2","rules":rules}).to_string(),
        )
        .unwrap();
        Self {
            _temp: temp,
            root,
            case,
            policy,
            original,
        }
    }

    async fn spawn(&self) -> (SocketAddr, Arc<ReplayRuntime>, tokio::task::JoinHandle<()>) {
        spawn_http_replay_with_policy(&self.case, vec![], Some(self.policy.clone()), None).await
    }

    fn assert_immutable(&self) {
        assert_eq!(
            std::fs::read(self.case.join("dependencies.jsonl")).unwrap(),
            self.original
        );
    }
}

async fn send(addr: SocketAddr, host: &str, uri: &str, body: &str) -> (StatusCode, Bytes) {
    let (mut sender, connection) =
        http1::handshake(TokioIo::new(TcpStream::connect(addr).await.unwrap()))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("host", host)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
                .unwrap(),
        )
        .await
        .unwrap();
    (
        response.status(),
        response.into_body().collect().await.unwrap().to_bytes(),
    )
}

#[tokio::test]
async fn http_json_jwt_rejects_invalid_fields_without_consumption_or_usage() {
    let fixture = Fixture::new(vec![], body(SOURCE, "a1b2c3d4")).await;
    let (addr, runtime, task) = fixture.spawn().await;
    let now = Utc::now().timestamp();
    let valid = body(now, "e5f6a7b8");
    let mut rejected = Vec::new();
    for (pointer, value) in [
        ("/model", json!("different-model")),
        ("/messages/0/content", json!("different input")),
        ("/metadata/business_id", json!(18)),
        ("/metadata/request_id", json!("bad")),
        ("/metadata/request_id", json!("g1234567")),
        ("/metadata/request_id", json!(12345678)),
        ("/metadata/auth_token", Value::Null),
        ("/metadata/auth_token", json!("not-a-jwt")),
        ("/metadata/skill_identity_token", json!({"token":"invalid"})),
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        rejected.push(invalid.to_string());
    }
    for field in ["request_id", "auth_token", "skill_identity_token"] {
        let mut invalid = valid.clone();
        invalid["metadata"].as_object_mut().unwrap().remove(field);
        rejected.push(invalid.to_string());
    }
    for (skill, algorithm, key, mutate) in [
        (false, Algorithm::HS256, "wrong-key", "none"),
        (true, Algorithm::HS256, "wrong-key", "none"),
        (false, Algorithm::HS512, KEY, "none"),
        (false, Algorithm::HS256, KEY, "subject"),
        (false, Algorithm::HS256, KEY, "roles"),
        (false, Algorithm::HS256, KEY, "lifetime"),
        (false, Algorithm::HS256, KEY, "missing-exp"),
        (true, Algorithm::HS256, KEY, "missing-iat"),
        (true, Algorithm::HS256, KEY, "iat-offset"),
    ] {
        let mut claims = claims(now, skill);
        match mutate {
            "subject" => claims["sub"] = json!("different-user"),
            "roles" => claims["roles"] = json!(["admin"]),
            "lifetime" => claims["exp"] = json!(now + 3660),
            "missing-exp" => {
                claims.as_object_mut().unwrap().remove("exp");
            }
            "missing-iat" => {
                claims.as_object_mut().unwrap().remove("iat");
            }
            "iat-offset" => claims["iat"] = json!(now - 60),
            "none" => (),
            _ => unreachable!(),
        }
        let mut invalid = valid.clone();
        invalid["metadata"][if skill {
            "skill_identity_token"
        } else {
            "auth_token"
        }] = json!(token(claims, algorithm, key));
        rejected.push(invalid.to_string());
    }
    rejected.push(body(SOURCE, "e5f6a7b8").to_string());
    let mut extra = valid.clone();
    extra["metadata"]["extra"] = json!(true);
    rejected.push(extra.to_string());
    rejected.push(format!(
        r#"{{"model":"stable-model","messages":{},"metadata":{},"metadata":{}}}"#,
        valid["messages"], valid["metadata"], valid["metadata"]
    ));
    for (index, invalid) in rejected.iter().enumerate() {
        assert_eq!(
            send(addr, HOST, URI, invalid).await.0,
            StatusCode::BAD_GATEWAY,
            "negative case {index}"
        );
    }
    for (host, uri) in [
        (HOST, "/other?mode=stable"),
        (HOST, "/chat?mode=changed"),
        ("other.example.test", URI),
    ] {
        assert_eq!(
            send(addr, host, uri, &valid.to_string()).await.0,
            StatusCode::BAD_GATEWAY
        );
    }
    {
        let state = runtime.state.lock().await;
        assert!(state.http_events.matched.is_empty());
        assert_eq!(
            state.unused_http_exchanges(ReplaySource::Case, false).len(),
            1
        );
        let report = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(report.dependency_rules[0].id, RULE);
        assert_eq!(report.dependency_rules[0].matches, 0);
        assert_eq!(report.dependency_rules[0].time_validations, 0);
    }
    let (status, response) = send(
        addr,
        HOST,
        URI,
        &body(Utc::now().timestamp(), "e5f6a7b8").to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response, "recorded-result");
    {
        let state = runtime.state.lock().await;
        assert_eq!(state.http_events.matched.len(), 1);
        assert!(
            state
                .unused_http_exchanges(ReplaySource::Case, false)
                .is_empty()
        );
        let report = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(report.dependency_rules[0].matches, 1);
        assert_eq!(report.dependency_rules[0].time_validations, 3);
    }
    assert_eq!(
        send(addr, HOST, URI, &valid.to_string()).await.0,
        StatusCode::BAD_GATEWAY
    );
    task.abort();
    fixture.assert_immutable();
}

#[tokio::test]
async fn http_json_jwt_clean_fresh_replay_delivers_both_tokens_with_new_clocks() {
    let fixture = Fixture::new(vec![], body(SOURCE, "a1b2c3d4")).await;
    let (addr, runtime, task) = fixture.spawn().await;
    assert_eq!(
        send(
            addr,
            HOST,
            URI,
            &body(Utc::now().timestamp(), "e5f6a7b8").to_string()
        )
        .await,
        (StatusCode::OK, Bytes::from_static(b"recorded-result"))
    );
    assert!(!runtime.state.lock().await.snapshot_report().is_dirty());
    task.abort();
    fixture.assert_immutable();
}

#[tokio::test]
async fn http_json_jwt_composes_with_disjoint_relative_time_and_unordered_fields() {
    let generated = json!({
        "id":"chat-window", "surface":"dependency.request",
        "match":{"api":"POST /scenario","resource":{"protocol":"http","endpoint":"api.example.test:80"},
            "operation":"POST","path":"/chat"},
        "slot":"body", "codec":"json",
        "contract":{
            "/requested_at":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"},
            "/tools":{"kind":"unordered"}
        },
        "proof":{"source":"synthetic/chat.rs:issue","fact":"Source requests carry the outbound request time and an unordered tool membership list"}
    });
    let mut source = body(SOURCE, "a1b2c3d4");
    source["requested_at"] = json!(SOURCE);
    source["tools"] = json!([{"id":"a","enabled":true},{"id":"b","enabled":false}]);
    let fixture = Fixture::new(vec![generated], source).await;
    let (addr, runtime, task) = fixture.spawn().await;
    let mut actual = body(Utc::now().timestamp(), "e5f6a7b8");
    actual["requested_at"] = json!(Utc::now().timestamp());
    actual["tools"] = json!([{"id":"b","enabled":false},{"id":"a","enabled":true}]);
    for (pointer, value) in [
        ("/requested_at", json!(SOURCE)),
        ("/tools/0/enabled", json!(true)),
        ("/model", json!("changed-model")),
    ] {
        let mut invalid = actual.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            send(addr, HOST, URI, &invalid.to_string()).await.0,
            StatusCode::BAD_GATEWAY
        );
    }
    {
        let state = runtime.state.lock().await;
        assert!(state.http_events.matched.is_empty());
        assert_eq!(
            state.unused_http_exchanges(ReplaySource::Case, false).len(),
            1
        );
        assert!(
            state
                .replay_policy
                .as_ref()
                .unwrap()
                .report()
                .dependency_rules
                .iter()
                .all(|row| row.matches == 0)
        );
    }
    assert_eq!(
        send(addr, HOST, URI, &actual.to_string()).await.0,
        StatusCode::OK
    );
    assert!(
        runtime
            .state
            .lock()
            .await
            .unused_http_exchanges(ReplaySource::Case, false)
            .is_empty()
    );
    task.abort();
    fixture.assert_immutable();
}

#[tokio::test]
async fn http_json_jwt_authenticates_before_identity_normalization_and_commits_together() {
    let identity = json!({
        "id":"chat-business-identity",
        "match":{"api":"POST /scenario","resource":{"protocol":"http","endpoint":"api.example.test:80"},
            "operation":"POST","path":"/chat"},
        "effect":{"kind":"identity","value_type":"string",
            "capture":{"kind":"http_json","pointer":"/metadata/business_id"},
            "references":[{"resource":{"protocol":"http","endpoint":"api.example.test:80"}}]},
        "proof":{"source":"synthetic/chat.rs:issue","fact":"Source creates a request-local business identity and reuses it only at this HTTP resource"}
    });
    let mut source = body(SOURCE, "a1b2c3d4");
    source["metadata"]["business_id"] = json!("Q");
    let fixture = Fixture::new(vec![identity], source).await;
    let (addr, runtime, task) = fixture.spawn().await;
    let now = Utc::now().timestamp();
    let mut invalid = body(now, "e5f6a7b8");
    invalid["metadata"]["business_id"] = json!("Z");
    invalid["metadata"]["auth_token"] =
        json!(token(claims(now, false), Algorithm::HS256, "wrong-key"));
    assert_eq!(
        send(addr, HOST, URI, &invalid.to_string()).await.0,
        StatusCode::BAD_GATEWAY
    );
    {
        let state = runtime.state.lock().await;
        assert!(state.http_events.matched.is_empty());
        assert_eq!(
            state.unused_http_exchanges(ReplaySource::Case, false).len(),
            1
        );
        let policy = state.replay_policy.as_ref().unwrap().report();
        assert!(policy.dynamic_bindings.is_empty());
        for id in [RULE, "chat-business-identity"] {
            let row = policy
                .dependency_rules
                .iter()
                .find(|row| row.id == id)
                .unwrap();
            assert_eq!(row.matches, 0);
            assert_eq!(row.time_validations, 0);
        }
    }
    // Both letters occur in every compact JWT header. Identity normalization
    // must see masked token fields, while signature validation sees original bytes.
    let mut actual = body(Utc::now().timestamp(), "e5f6a7b8");
    actual["metadata"]["business_id"] = json!("J");
    let compact = actual["metadata"]["auth_token"].as_str().unwrap();
    assert!(compact.contains('Q') && compact.contains('J'));
    assert_eq!(
        send(addr, HOST, URI, &actual.to_string()).await,
        (StatusCode::OK, Bytes::from_static(b"recorded-result"))
    );
    {
        let state = runtime.state.lock().await;
        assert_eq!(state.http_events.matched.len(), 1);
        assert!(
            state
                .unused_http_exchanges(ReplaySource::Case, false)
                .is_empty()
        );
        let policy = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(policy.dynamic_bindings.len(), 1);
        for id in [RULE, "chat-business-identity"] {
            let row = policy
                .dependency_rules
                .iter()
                .find(|row| row.id == id)
                .unwrap();
            assert_eq!(row.matches, 1);
        }
        let jwt = policy
            .dependency_rules
            .iter()
            .find(|row| row.id == RULE)
            .unwrap();
        assert_eq!(jwt.time_validations, 3);
    }
    assert_eq!(
        send(addr, HOST, URI, &actual.to_string()).await.0,
        StatusCode::BAD_GATEWAY
    );
    task.abort();
    fixture.assert_immutable();
}

#[tokio::test]
async fn http_json_jwt_source_self_validation_authenticates_immutable_recording() {
    use crate::replay::{NativeSourceCase, validate_native_source_dependencies};
    let fixture = Fixture::new(vec![], body(SOURCE, "a1b2c3d4")).await;
    let compiled = crate::policy::compile_policy(
        &crate::policy::parse_policy(&std::fs::read_to_string(&fixture.policy).unwrap()).unwrap(),
    )
    .unwrap();
    let request: Value =
        serde_json::from_slice(&std::fs::read(fixture.case.join("request.json")).unwrap()).unwrap();
    let event: Value = serde_json::from_slice(&fixture.original).unwrap();
    let selected = BTreeSet::from([RULE.to_owned()]);
    let check = |events: &[Value]| {
        validate_native_source_dependencies(
            &compiled,
            &selected,
            &fixture.root,
            &[NativeSourceCase {
                id: "case",
                dir: &fixture.case,
                request: &request,
                events,
            }],
        )
    };
    let checked = check(std::slice::from_ref(&event)).unwrap();
    assert_eq!(checked.rules[RULE], 1);
    assert!(!checked.key_witnesses.is_empty());
    for invalid_body in [
        {
            let mut value = body(SOURCE, "a1b2c3d4");
            value["metadata"]["auth_token"] =
                json!(token(claims(SOURCE, false), Algorithm::HS256, "wrong-key"));
            value
        },
        {
            let mut value = body(SOURCE, "a1b2c3d4");
            value["metadata"]["auth_token"] =
                json!(token(claims(SOURCE, false), Algorithm::HS512, KEY));
            value
        },
        body(SOURCE, "invalid"),
        {
            let mut value = body(SOURCE, "a1b2c3d4");
            value["metadata"]["auth_token"] = json!(token(
                json!({"sub":"user-17","roles":["reader"],"exp":SOURCE-1}),
                Algorithm::HS256,
                KEY
            ));
            value
        },
    ] {
        let mut invalid = event.clone();
        invalid["request_body"] = body_capture(&invalid_body.to_string());
        assert!(check(&[invalid]).is_err());
    }
    fixture.assert_immutable();
}
