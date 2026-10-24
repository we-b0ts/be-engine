//! Global JWT verification retains real HTTP envelope and finite-consumption checks.
use super::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;

const KEY: &str = "synthetic-http-body-signing-key";
const SOURCE: i64 = 1_700_000_000;
const HOST: &str = "api.example.test";
const URI: &str = "/chat?mode=stable";

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
            "token_copy":token(claims(now, false), Algorithm::HS256, KEY),
            "skill_identity_token":token(claims(now, true), Algorithm::HS256, KEY),
            "business_id":17
        }
    })
}

fn rule() -> Value {
    json!({"format":"traffic-policy/v2","signatures":{
        "default":{"kind":"jwt","algorithm":"HS256","key":{"kind":"target_env","name":"SECRET_KEY"}}
    },"json":{"fields":{
        "/metadata/request_id":{"kind":"identity","formats":[{"hex":8}]},
        "/metadata/auth_token":{"kind":"jwt"},
        "/metadata/skill_identity_token":{"kind":"jwt"},
        "/metadata/token_copy":{"kind":"jwt"}
    }}})
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
        std::fs::write(
            root.join(crate::repository::LOCAL_TARGET_ENV_PATH),
            format!("SECRET_KEY={KEY}\n"),
        )
        .unwrap();
        // The original request evidence uses the same managed encryption boundary
        // as production. Signing material remains a separate private startup input.
        let key_path = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        std::fs::write(
            key_path,
            crate::request_headers::generate_encryption_key().unwrap(),
        )
        .unwrap();
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
        let mut document = rule();
        for extra in extra_rules {
            document["json"]["fields"]
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
        }
        crate::replay::write_policy_fixture(&policy, document.to_string()).unwrap();
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
async fn global_http_jwt_verification_preserves_full_identity_and_finite_consumption() {
    let fixture = Fixture::new(vec![], body(SOURCE, "a1b2c3d4")).await;
    assert!(
        fixture
            .root
            .join(crate::repository::LOCAL_TARGET_ENV_PATH)
            .is_file()
    );
    let (addr, runtime, task) = fixture.spawn().await;
    let valid = body(Utc::now().timestamp(), "e5f6a7b8");
    let mut rejected = Vec::new();
    for (pointer, value) in [
        ("/model", json!("changed")),
        ("/metadata/business_id", json!(18)),
        ("/metadata/request_id", json!("bad")),
        ("/metadata/request_id", json!("g1234567")),
        ("/metadata/auth_token", json!("not-a-jwt")),
        (
            "/metadata/auth_token",
            json!(token(
                claims(Utc::now().timestamp(), false),
                Algorithm::HS512,
                KEY
            )),
        ),
        (
            "/metadata/auth_token",
            json!(token(
                claims(Utc::now().timestamp(), false),
                Algorithm::HS256,
                "wrong-key"
            )),
        ),
        (
            "/metadata/auth_token",
            json!(token(
                json!({"sub":"other-user","roles":["reader"],"exp":Utc::now().timestamp()+3600}),
                Algorithm::HS256,
                KEY
            )),
        ),
        ("/metadata/auth_token", Value::Null),
        (
            "/metadata/token_copy",
            valid["metadata"]["skill_identity_token"].clone(),
        ),
        (
            "/metadata/skill_identity_token",
            valid["metadata"]["auth_token"].clone(),
        ),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        rejected.push(changed.to_string());
    }
    let mut absent = valid.clone();
    absent["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("auth_token");
    rejected.push(absent.to_string());
    rejected.push(format!(
        r#"{{"model":"stable-model","messages":{},"metadata":{},"metadata":{}}}"#,
        valid["messages"], valid["metadata"], valid["metadata"]
    ));
    for body in rejected {
        assert_eq!(
            send(addr, HOST, URI, &body).await.0,
            StatusCode::BAD_GATEWAY
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
        assert_eq!(
            state
                .replay_policy
                .as_ref()
                .unwrap()
                .report()
                .global_formats[0]
                .validations,
            0
        );
    }
    assert_eq!(
        send(addr, HOST, URI, &valid.to_string()).await,
        (StatusCode::OK, Bytes::from_static(b"recorded-result"))
    );
    assert_eq!(
        send(addr, HOST, URI, &valid.to_string()).await.0,
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(runtime.state.lock().await.http_events.matched.len(), 1);
    task.abort();
    fixture.assert_immutable();
}

#[tokio::test]
async fn global_http_jwt_verification_composes_with_time_and_unordered_business_fields() {
    let fields = json!({"/requested_at":{"kind":"time","formats":["unix_seconds"]},"/tools":{"kind":"unordered"}});
    let mut source = body(SOURCE, "a1b2c3d4");
    source["requested_at"] = json!(SOURCE);
    source["tools"] = json!([{"id":"a","enabled":true},{"id":"b","enabled":false}]);
    let fixture = Fixture::new(vec![fields], source).await;
    let (addr, runtime, task) = fixture.spawn().await;
    let mut valid = body(Utc::now().timestamp(), "e5f6a7b8");
    valid["requested_at"] = json!(Utc::now().timestamp());
    valid["tools"] = json!([{"id":"b","enabled":false},{"id":"a","enabled":true}]);
    for (pointer, value) in [
        ("/requested_at", json!(SOURCE + 1)),
        ("/tools/0/enabled", json!(true)),
        ("/model", json!("changed")),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            send(addr, HOST, URI, &changed.to_string()).await.0,
            StatusCode::BAD_GATEWAY
        );
    }
    assert_eq!(
        send(addr, HOST, URI, &valid.to_string()).await.0,
        StatusCode::OK
    );
    let state = runtime.state.lock().await;
    assert!(
        state
            .unused_http_exchanges(ReplaySource::Case, false)
            .is_empty()
    );
    assert_eq!(
        state
            .replay_policy
            .as_ref()
            .unwrap()
            .report()
            .global_formats[0]
            .time_validations,
        5
    );
    drop(state);
    task.abort();
    fixture.assert_immutable();
}

#[tokio::test]
async fn repeated_http_requests_require_the_same_verified_complete_jwt_correspondence() {
    let mut fixture = Fixture::new(vec![], body(SOURCE, "a1b2c3d4")).await;
    let event: Value = serde_json::from_slice(&fixture.original).unwrap();
    let mut second = event.clone();
    second["id"] = json!(uuid::Uuid::new_v4());
    fixture.original = format!("{event}\n{second}\n").into_bytes();
    std::fs::write(fixture.case.join("dependencies.jsonl"), &fixture.original).unwrap();
    let (addr, runtime, task) = fixture.spawn().await;
    let now = Utc::now().timestamp();
    let valid = body(now, "e5f6a7b8");
    assert_eq!(
        send(addr, HOST, URI, &valid.to_string()).await.0,
        StatusCode::OK
    );
    // Both signatures and relative times are valid; the complete Source token
    // must still retain its first accepted Target counterpart.
    let conflicting = body(now + 1, "e5f6a7b8");
    assert_eq!(
        send(addr, HOST, URI, &conflicting.to_string()).await.0,
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .unused_http_exchanges(ReplaySource::Case, false)
            .len(),
        1
    );
    assert_eq!(
        send(addr, HOST, URI, &valid.to_string()).await.0,
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
