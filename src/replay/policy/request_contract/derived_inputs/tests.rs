use super::*;
use serde_json::json;

fn fixture(
    duplicate: bool,
) -> (
    tempfile::TempDir,
    RequestContracts,
    Value,
    Arc<crate::policy::CompiledPolicy>,
) {
    let root = tempfile::tempdir().unwrap();
    let local = root.path().join(".traffic-e2e/local");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("target.env"), "SECRET=test-key\n").unwrap();
    let token = crate::request_rules::tests::token(
        json!({"iat":1000,"exp":1060,"role":"reader"}),
        "test-key",
    );
    let body = if duplicate {
        json!({"copy":token})
    } else {
        json!({"stable":1})
    };
    let source = json!({"method":"GET","uri":format!("/api?download_token={token}&id=11111111-1111-4111-8111-111111111111"),"timestamp":"1970-01-01T00:16:40Z","headers":{},"body":{"encoding":"utf8","data":body.to_string(),"truncated":false}});
    let directory = root.path().join("case");
    std::fs::create_dir(&directory).unwrap();
    let raw = serde_json::to_vec(&source).unwrap();
    std::fs::write(directory.join("request.json"), &raw).unwrap();
    let compiled=Arc::new(crate::policy::parse_and_compile_policy(&json!({"format":"traffic-policy/v2","json":{"fields":{"/access_token":{"kind":"identity","formats":["string"]}}},"rules":[{
        "id":"input-token","match":{"api":"GET /api"},"effect":{"kind":"input_jwt","location":{"kind":"query","name":"download_token"},"algorithm":"HS256","time":"preserve_relative","signing_key":{"kind":"target_env","name":"SECRET"}},"proof":{"source":"auth.py:1-20","fact":"Source verifies the signed query token and uses relative expiry"}
    }]}).to_string()).unwrap());
    let mut owner = RequestContracts::from_source_policy(
        &[],
        root.path(),
        &BTreeMap::from([("case".into(), (directory, source.clone()))]),
    )
    .unwrap();
    owner.configure_compiled(Some(compiled.clone())).unwrap();
    let mut state = owner.state.lock().unwrap();
    state.cases.get_mut("case").unwrap().actual = Some(Utc::now() - chrono::TimeDelta::seconds(2));
    state
        .source_request_digests
        .insert("case".into(), crate::policy_evidence::digest(&raw));
    drop(state);
    (root, owner, source, compiled)
}
fn shifted(
    root: &Path,
    compiled: &crate::policy::CompiledPolicy,
    source: &Value,
    at: DateTime<Utc>,
) -> Value {
    let runtime = crate::request_rules::RequestRuleRuntime::from_compiled(root, compiled).unwrap();
    let mut actual = source.clone();
    runtime.apply(&mut actual, at).unwrap();
    actual
}
fn token(request: &Value) -> String {
    let uri = request["uri"]
        .as_str()
        .unwrap()
        .parse::<hyper::Uri>()
        .unwrap();
    ::url::form_urlencoded::parse(uri.query().unwrap().as_bytes())
        .find(|(name, _)| name == "download_token")
        .unwrap()
        .1
        .into_owned()
}
fn pair(source: &str, target: &str) -> IdentityPair {
    IdentityPair {
        source: serde_json::to_string(source).unwrap(),
        target: serde_json::to_string(target).unwrap(),
    }
}

#[test]
fn only_exact_reconstructed_delivery_can_override_a_fixed_input_anchor() {
    let (root, owner, source, compiled) = fixture(false);
    let at = Utc::now();
    let actual = shifted(root.path(), &compiled, &source, at);
    let expected = pair(&token(&source), &token(&actual));
    assert!(
        owner
            .preview_identity_pairs("case", std::slice::from_ref(&expected))
            .is_err()
    );
    let prepared = owner.prepare_derived_inputs("case", at, &actual).unwrap();
    assert!(!owner.has_identities("case"));
    owner.commit_derived_inputs(prepared).unwrap();
    assert_eq!(owner.request_times("case").target, Some(at));
    assert!(
        owner
            .preview_identity_pairs("case", std::slice::from_ref(&expected))
            .is_ok()
    );
    assert!(
        owner
            .preview_identity_pairs("case", &[pair(&token(&source), &token(&source))])
            .is_err()
    );
    assert!(
        owner
            .preview_identity_pairs(
                "case",
                &[pair(
                    "11111111-1111-4111-8111-111111111111",
                    "22222222-2222-4222-8222-222222222222"
                )]
            )
            .is_err()
    );
    let later = shifted(
        root.path(),
        &compiled,
        &source,
        at + chrono::TimeDelta::seconds(10),
    );
    assert!(
        owner
            .preview_identity_pairs("case", &[pair(&token(&source), &token(&later))])
            .is_err()
    );
}

#[test]
fn tampered_input_wrong_send_clock_duplicate_source_and_changed_key_never_commit() {
    let (root, owner, source, compiled) = fixture(false);
    let at = Utc::now();
    let actual = shifted(root.path(), &compiled, &source, at);
    let mut wrong = actual.clone();
    wrong["uri"] = json!(actual["uri"].as_str().unwrap().replace("id=111", "id=999"));
    assert!(owner.prepare_derived_inputs("case", at, &wrong).is_err());
    assert!(
        owner
            .prepare_derived_inputs("case", at - chrono::TimeDelta::seconds(1), &actual)
            .is_err()
    );
    assert!(!owner.has_identities("case"));
    let prepared = owner.prepare_derived_inputs("case", at, &actual).unwrap();
    std::fs::write(
        root.path().join(".traffic-e2e/local/target.env"),
        "SECRET=changed\n",
    )
    .unwrap();
    assert!(owner.commit_derived_inputs(prepared).is_err());
    assert!(!owner.has_identities("case"));
    let (root, owner, source, compiled) = fixture(true);
    let at = Utc::now();
    let actual = shifted(root.path(), &compiled, &source, at);
    assert!(owner.prepare_derived_inputs("case", at, &actual).is_err());
    assert!(!owner.has_identities("case"));
    let path = root.path().join("case/request.json");
    std::fs::write(path, source.to_string() + " ").unwrap();
    assert!(owner.prepare_derived_inputs("case", at, &actual).is_err());
}

#[tokio::test]
async fn actual_client_registers_re_signed_input_before_http_exposure() {
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
    let (root, owner, source, compiled) = fixture(false);
    let socket = root.path().join("control.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let session = root.path().join("session.json");
    std::fs::write(&session, json!({"control_socket":socket}).to_string()).unwrap();
    let admitted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let registering = owner.clone();
    let registered = admitted.clone();
    let control = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["command"], "derived_input");
        let at = serde_json::from_value(value["derived_input"]["request_sent_at"].clone()).unwrap();
        let prepared = registering
            .prepare_derived_inputs("case", at, &value["derived_input"]["request"])
            .unwrap();
        registering.commit_derived_inputs(prepared).unwrap();
        registered.store(true, std::sync::atomic::Ordering::SeqCst);
        reader
            .get_mut()
            .write_all(b"{\"ok\":true}\n")
            .await
            .unwrap();
        at
    });
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", http.local_addr().unwrap());
    let source_token = token(&source);
    let observing = owner.clone();
    let target = tokio::spawn(async move {
        let (mut stream, _) = http.accept().await.unwrap();
        let mut header = Vec::new();
        let mut byte = [0];
        while !header.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            header.push(byte[0]);
        }
        assert!(admitted.load(std::sync::atomic::Ordering::SeqCst));
        let raw = String::from_utf8(header).unwrap();
        let uri = raw
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        let actual = token(&json!({"uri":uri}));
        assert!(
            observing
                .knows_native_identity("case", &source_token, &actual)
                .unwrap()
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .await
            .unwrap();
    });
    let runtime = Arc::new(
        crate::request_rules::RequestRuleRuntime::from_compiled(root.path(), &compiled).unwrap(),
    );
    let response = crate::recorded_request::RecordedHttpClient::new(
        origin,
        std::time::Duration::from_secs(5),
        1024,
    )
    .with_request_rule_runtime(runtime)
    .with_input_registration(&session, "case")
    .send_bytes(
        &serde_json::to_vec(&source).unwrap(),
        root.path().join("case/request.json").to_str().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status, hyper::StatusCode::OK);
    assert_eq!(response.request_sent_at, control.await.unwrap());
    target.await.unwrap();
}
