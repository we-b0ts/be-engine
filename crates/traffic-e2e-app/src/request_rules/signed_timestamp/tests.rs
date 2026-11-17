use super::*;
use serde_json::json;

fn definition() -> Value {
    json!({"id":"login-time","match":{"api":"POST /login"},"effect":{
        "kind":"input_signed_timestamp","algorithm":"md5_sorted_fields",
        "fields":{"username":"/username","source":"/source","timestamp":"/timestamp"},
        "timestamp_pointer":"/timestamp","signature_pointer":"/sign","secret_parameter":"secret_key",
        "signing_key":{"kind":"target_env","name":"LOGIN_SECRET"},"time":"preserve_relative"},
        "proof":{"source":"login.py:verify","fact":"The source verifies MD5 of sorted trimmed string fields with a startup secret and checks the timestamp window"}})
}

fn effect() -> InputSignedTimestampEffect {
    serde_json::from_value({
        let mut effect = definition()["effect"].clone();
        effect.as_object_mut().unwrap().remove("kind");
        effect
    })
    .unwrap()
}

// Independently spell the application's signature recipe, rather than use the
// engine's configured field traversal to produce its own expected answer.
fn source_request(timestamp: i64) -> Value {
    let sign = format!(
        "{:x}",
        Md5::digest(format!(
            "source=desk&timestamp={timestamp}&username=user&secret_key=test-key"
        ))
    );
    json!({"method":"POST","uri":"/login","timestamp":"1970-01-01T00:16:40Z", "headers":{"content-type":["application/json"]},
        "body":{"encoding":"utf8","truncated":false,"data":json!({"source":"desk","username":"user","timestamp":timestamp.to_string(),"sign":sign,"untouched":{"roles":["reader"]}}).to_string()}})
}

#[test]
fn relative_translation_preserves_both_validity_and_invalidity_with_independent_signature_check() {
    for timestamp in [995, 600, 1400] {
        for encoding in ["utf8", "base64"] {
            let mut request = source_request(timestamp);
            if encoding == "base64" {
                request["body"]["data"] = STANDARD
                    .encode(request["body"]["data"].as_str().unwrap())
                    .into();
                request["body"]["encoding"] = encoding.into();
            }
            let original = request.clone();
            let observation = apply(
                &mut request,
                &effect(),
                b"test-key",
                DateTime::from_timestamp(5000, 0).unwrap(),
            )
            .unwrap()
            .unwrap();
            let body = body(&request).unwrap().unwrap();
            let shifted = body["timestamp"].as_str().unwrap().parse::<i64>().unwrap();
            assert_eq!(shifted - 5000, timestamp - 1000);
            assert_eq!(
                body["sign"],
                format!(
                    "{:x}",
                    Md5::digest(format!(
                        "source=desk&timestamp={shifted}&username=user&secret_key=test-key"
                    ))
                )
            );
            assert_eq!(body["untouched"], json!({"roles":["reader"]}));
            assert_eq!(observation.offset_seconds, Some(4000));
            assert_eq!(request["headers"], original["headers"]);
            assert_eq!(request["uri"], original["uri"]);
            assert_eq!(request["timestamp"], original["timestamp"]);
        }
    }
}

#[test]
fn invalid_signatures_and_ambiguous_or_incomplete_json_are_never_reissued() {
    let mut request = source_request(995);
    let original = request.clone();
    assert_eq!(
        apply(&mut request, &effect(), b"wrong-key", Utc::now())
            .unwrap()
            .unwrap()
            .outcome,
        "original_signature_invalid_unchanged"
    );
    assert_eq!(request, original);
    request["body"]["data"] = json!(r#"{"timestamp":"995","timestamp":"996","sign":"bad"}"#);
    let original = request.clone();
    assert!(
        apply(&mut request, &effect(), b"test-key", Utc::now())
            .unwrap()
            .is_none()
    );
    assert_eq!(request, original);
    request["body"]["truncated"] = true.into();
    assert!(apply(&mut request, &effect(), b"test-key", Utc::now()).is_err());
}

#[test]
fn compiler_rejects_unbounded_and_overlapping_signature_recipes() {
    let compile = |rule: Value| {
        crate::policy::compile_policy(
            &serde_json::from_value(json!({"format":"traffic-policy/v3","rules":[rule]})).unwrap(),
        )
    };
    assert!(compile(definition()).is_ok());
    for (field, value) in [
        ("timestamp_pointer", json!("/absent")),
        ("signature_pointer", json!("/timestamp")),
        ("signature_pointer", json!("/timestamp/child")),
        (
            "fields",
            json!({"timestamp":"/timestamp","duplicate":"/timestamp"}),
        ),
        (
            "fields",
            json!({"timestamp":"/timestamp","bad&parameter":"/value"}),
        ),
        ("secret_parameter", json!("timestamp")),
    ] {
        let mut bad = definition();
        bad["effect"][field] = value;
        assert!(compile(bad).is_err(), "{field}");
    }
    let mut bad = definition();
    bad["match"] = json!({});
    assert!(compile(bad).is_err());
    let mut second = definition();
    second["id"] = "overlap".into();
    let policy =
        serde_json::from_value(json!({"format":"traffic-policy/v3","rules":[definition(),second]}))
            .unwrap();
    assert!(crate::policy::compile_policy(&policy).is_err());
}

#[tokio::test]
async fn genuine_http_send_uses_source_signature_and_keeps_recording_immutable() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let temp = tempfile::tempdir().unwrap();
    let env = temp.path().join(crate::repository::LOCAL_TARGET_ENV_PATH);
    std::fs::create_dir_all(env.parent().unwrap()).unwrap();
    std::fs::write(&env, "LOGIN_SECRET=test-key\n").unwrap();
    let policy = temp.path().join("policy.yaml");
    std::fs::write(
        &policy,
        json!({"format":"traffic-policy/v3","rules":[definition()]}).to_string(),
    )
    .unwrap();
    let path = temp.path().join("request.json");
    let original = source_request(995).to_string();
    std::fs::write(&path, &original).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let (start, length) = loop {
            let mut buffer = [0; 4096];
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buffer[..n]);
            if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|s| s.parse::<usize>().ok())
                    })
                    .unwrap();
                if bytes.len() >= end + 4 + length {
                    break (end + 4, length);
                }
            }
        };
        let body: Value = serde_json::from_slice(&bytes[start..start + length]).unwrap();
        let timestamp = body["timestamp"].as_str().unwrap();
        assert!((Utc::now().timestamp() - timestamp.parse::<i64>().unwrap() - 5).abs() <= 1);
        assert_eq!(
            body["sign"],
            format!(
                "{:x}",
                Md5::digest(format!(
                    "source=desk&timestamp={timestamp}&username=user&secret_key=test-key"
                ))
            )
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let response = crate::recorded_request::RecordedHttpClient::new(
        format!("http://{address}"),
        std::time::Duration::from_secs(5),
        1024,
    )
    .with_request_rules(temp.path(), &policy)
    .unwrap()
    .send(&path)
    .await
    .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.request_rules[0].rule_id, "login-time");
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
    server.await.unwrap();
}
