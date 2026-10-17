use super::*;
use crate::replay::{ResponseAssertionOptions, ResponseDifferenceKind, assert_recorded_response};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::path::Path;

mod keys;
mod rsa;
mod url;

const KEY: &str = "response-jwt-test-signing-key";
const SOURCE: i64 = 1_700_000_000;
const TARGET: i64 = SOURCE + 86_400;

fn write(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn claims(time: i64) -> Value {
    json!({"sub":"user", "roles":["reader"], "iss":"issuer", "aud":"connector",
        "iat":time, "nbf":time-1, "exp":time+1800})
}

fn token(claims: &Value, algorithm: Algorithm, key: &str) -> String {
    encode(
        &Header::new(algorithm),
        claims,
        &EncodingKey::from_secret(key.as_bytes()),
    )
    .unwrap()
}

fn copy(options: &ResponseAssertionOptions) -> ResponseAssertionOptions {
    ResponseAssertionOptions {
        case_id: options.case_id.clone(),
        request: options.request.clone(),
        expected_response: options.expected_response.clone(),
        actual_response: options.actual_response.clone(),
        policy: options.policy.clone(),
    }
}

fn fixture() -> (
    tempfile::TempDir,
    ResponseAssertionOptions,
    ResponseJwtRuleFeedback,
) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir_all(root.join(".traffic-e2e/local")).unwrap();
    fs::write(
        root.join(".traffic-e2e/local/target.env"),
        format!("SECRET_KEY={KEY}\n"),
    )
    .unwrap();
    let options = ResponseAssertionOptions {
        case_id: "case".into(),
        request: root.join("request.json"),
        expected_response: root.join("expected.json"),
        actual_response: root.join("actual.json"),
        policy: root.join(".traffic-e2e/policy.yaml"),
    };
    crate::replay::write_policy_fixture(
        &options.policy,
        "# retained\nversion: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    write(
        &options.request,
        &json!({"method":"POST","uri":"/connector/token",
        "timestamp":chrono::DateTime::from_timestamp(SOURCE,0).unwrap()}),
    );
    write(
        &options.expected_response,
        &json!({"status":200,"headers":{},"body":{"encoding":"utf8",
        "data":json!({"access_token":token(&claims(SOURCE),Algorithm::HS256,KEY),"token_type":"bearer"}).to_string(),
        "truncated":false}}),
    );
    write(
        &options.actual_response,
        &json!({"version":1,"status":200,"headers":{},
        "request_sent_at":chrono::DateTime::from_timestamp(TARGET,0).unwrap(),
        "body":{"encoding":"utf8","data":json!({"access_token":token(&claims(TARGET),Algorithm::HS256,KEY),
        "token_type":"bearer"}).to_string(),"truncated":false}}),
    );
    let report = assert_recorded_response(copy(&options)).unwrap();
    assert!(!report.passed);
    let detail = root.join("detail.json");
    let bytes = serde_json::to_vec(&report).unwrap();
    fs::write(&detail, &bytes).unwrap();
    let assertion_report = root.join("assertions.json");
    let aggregate_report = root.join("aggregate.json");
    write(
        &assertion_report,
        &json!({"version":4,"case_source":root,"expected_response":"assertions_only",
        "assertion_mode":"runner_owned","policy_fingerprint":report.policy_fingerprint,
        "cases":[{"case_id":"case","response":{"method":"POST","path":"/connector/token",
        "detail_report":detail,"detail_fingerprint":fingerprint(&bytes)}}]}),
    );
    write(
        &aggregate_report,
        &json!({"case_source":root,"selected_case_ids":["case"],"complete":true,"dirty":false}),
    );
    let feedback = ResponseJwtRuleFeedback { policy_path: options.policy.clone(), api:"POST /connector/token".into(),
        rules: vec![serde_json::from_value(json!({"pointer":"/access_token","algorithm":"HS256",
            "signing_key_source":{"kind":"target_env","name":"SECRET_KEY"},
            "source_evidence":"Connector:issue signs identity claims and a 30-minute JWT using SECRET_KEY"})).unwrap()],
        evidence: ResponseBodyRuleEvidence::FocusedE2e { assertion_report, aggregate_report },
    };
    (temp, options, feedback)
}

// This writes an explicit synthetic rule fixture; no production authoring API
// or fallback accepts the old DTO. Actual assertions use the compiled new AST.
fn install_jwt_fixture(feedback: ResponseJwtRuleFeedback) -> Result<()> {
    let mut document = load_replay_policy(&feedback.policy_path)?.document;
    document
        .response_rules
        .json
        .entry(feedback.api)
        .or_default()
        .jwt = feedback.rules;
    crate::replay::write_policy_fixture(&feedback.policy_path, serde_yaml::to_string(&document)?)
}
fn fixture_policy_view(path: &Path) -> Value {
    serde_json::to_value(load_replay_policy(path).unwrap().document).unwrap()
}

fn change_body(
    options: &ResponseAssertionOptions,
    expected: bool,
    change: impl FnOnce(&mut Value),
) {
    let path = if expected {
        &options.expected_response
    } else {
        &options.actual_response
    };
    let mut response: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let mut body: Value = serde_json::from_str(response["body"]["data"].as_str().unwrap()).unwrap();
    change(&mut body);
    response["body"]["data"] = json!(body.to_string());
    write(path, &response);
}

#[test]
fn response_jwt_plan_apply_preserves_recording_and_checks_fresh_execution() {
    let (_temp, options, feedback) = fixture();
    let original = fs::read(&options.expected_response).unwrap();
    install_jwt_fixture(feedback).unwrap();
    assert_eq!(fs::read(&options.expected_response).unwrap(), original);
    let report = assert_recorded_response(copy(&options)).unwrap();
    assert!(report.passed, "{:?}", report.differences);
    assert_eq!(report.applied_body_rule_ids.len(), 1);
    change_body(&options, false, |body| body["token_type"] = json!("other"));
    assert!(!assert_recorded_response(options).unwrap().passed);
}

#[test]
fn response_jwt_rejects_signature_identity_time_and_shape_defects() {
    for defect in [
        "source_signature",
        "target_signature",
        "algorithm",
        "identity",
        "roles",
        "audience",
        "expired",
        "lifetime",
        "future_iat",
        "future_nbf",
        "missing_exp",
        "missing_iat",
        "fractional_time",
        "malformed",
        "null",
        "missing",
        "identical_old_token",
    ] {
        let (_temp, options, feedback) = fixture();
        install_jwt_fixture(feedback).unwrap();
        let mut value = claims(TARGET);
        let mut key = KEY;
        let mut algorithm = Algorithm::HS256;
        match defect {
            "identity" => value["sub"] = json!("another-user"),
            "roles" => value["roles"] = json!(["admin"]),
            "audience" => value["aud"] = json!("other"),
            "expired" => value["exp"] = json!(TARGET),
            "lifetime" => value["exp"] = json!(TARGET + 1806),
            "future_iat" => value["iat"] = json!(TARGET + 6),
            "future_nbf" => value["nbf"] = json!(TARGET + 6),
            "missing_exp" => {
                value.as_object_mut().unwrap().remove("exp");
            }
            "missing_iat" => {
                value.as_object_mut().unwrap().remove("iat");
            }
            "fractional_time" => value["exp"] = json!(TARGET as f64 + 1800.5),
            "target_signature" => key = "wrong-key",
            "algorithm" => algorithm = Algorithm::HS384,
            "identical_old_token" => value = claims(SOURCE),
            _ => (),
        }
        let replacement = token(&value, algorithm, key);
        change_body(&options, false, |body| {
            body["access_token"] = json!(replacement);
            if defect == "malformed" {
                body["access_token"] = json!("not-a-jwt");
            }
            if defect == "null" {
                body["access_token"] = Value::Null;
            }
            if defect == "missing" {
                body.as_object_mut().unwrap().remove("access_token");
            }
        });
        if defect == "source_signature" {
            change_body(&options, true, |body| {
                body["access_token"] = json!(token(&claims(SOURCE), Algorithm::HS256, "wrong-key"))
            });
        }
        let report = assert_recorded_response(options).unwrap();
        assert!(!report.passed, "{defect}");
        assert!(!report.differences.is_empty(), "{defect}");
        assert!(!serde_json::to_string(&report).unwrap().contains(KEY));
    }
}

#[test]
fn response_jwt_five_second_window_is_inclusive_and_uses_request_anchors() {
    for offset in [-6, -5, 5, 6] {
        let (_temp, options, feedback) = fixture();
        install_jwt_fixture(feedback).unwrap();
        change_body(&options, false, |body| {
            body["access_token"] = json!(token(&claims(TARGET + offset), Algorithm::HS256, KEY))
        });
        assert_eq!(
            assert_recorded_response(options).unwrap().passed,
            offset.abs() <= 5,
            "{offset}"
        );
    }
    let (_temp, options, feedback) = fixture();
    install_jwt_fixture(feedback).unwrap();
    let mut response: Value =
        serde_json::from_slice(&fs::read(&options.actual_response).unwrap()).unwrap();
    response.as_object_mut().unwrap().remove("request_sent_at");
    write(&options.actual_response, &response);
    let report = assert_recorded_response(options).unwrap();
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::TimeReferenceMissing
    );
}

#[test]
fn old_response_jwt_authoring_is_retired_without_writing() {
    let (_temp, options, feedback) = fixture();
    let original = fs::read(&options.policy).unwrap();
    let error = plan_response_jwt_rule(feedback).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("legacy rule authoring is retired")
    );
    assert_eq!(fs::read(&options.policy).unwrap(), original);
}

#[test]
fn response_jwt_wildcard_binds_uuid_jti_and_rejects_many_to_one() {
    let (_temp, options, feedback) = fixture();
    install_jwt_fixture(feedback).unwrap();
    let mut policy: Value = fixture_policy_view(&options.policy);
    policy["response_rules"]["json"]["POST /connector/token"]["jwt"][0]["pointer"] =
        json!("/items/*/token");
    policy["response_rules"]["json"]["POST /connector/token"]["jwt"][0]["dynamic_claims"] =
        json!(["/jti"]);
    crate::replay::write_policy_fixture(&options.policy, serde_yaml::to_string(&policy).unwrap())
        .unwrap();
    let left = uuid::Uuid::new_v4().to_string();
    let right = uuid::Uuid::new_v4().to_string();
    let make = |time, nonce: &str| {
        let mut c = claims(time);
        c["jti"] = json!(nonce);
        token(&c, Algorithm::HS256, KEY)
    };
    change_body(
        &options,
        true,
        |body| *body = json!({"items":[{"token":make(SOURCE,&left)},{"token":make(SOURCE,&left)}]}),
    );
    change_body(
        &options,
        false,
        |body| {
            *body = json!({"items":[{"token":make(TARGET,&right)},{"token":make(TARGET,&right)}]})
        },
    );
    assert!(assert_recorded_response(copy(&options)).unwrap().passed);
    change_body(&options, true, |body| {
        body["items"][1]["token"] = json!(make(SOURCE, &uuid::Uuid::new_v4().to_string()))
    });
    let report = assert_recorded_response(options).unwrap();
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::JwtNonceMismatch
    );
}

#[test]
fn response_jwt_all_hmac_algorithms_and_strict_declarations() {
    for (name, algorithm) in [
        ("HS256", Algorithm::HS256),
        ("HS384", Algorithm::HS384),
        ("HS512", Algorithm::HS512),
    ] {
        let (_temp, options, feedback) = fixture();
        install_jwt_fixture(feedback).unwrap();
        let mut policy: Value = fixture_policy_view(&options.policy);
        policy["response_rules"]["json"]["POST /connector/token"]["jwt"][0]["algorithm"] =
            json!(name);
        crate::replay::write_policy_fixture(
            &options.policy,
            serde_yaml::to_string(&policy).unwrap(),
        )
        .unwrap();
        change_body(&options, true, |body| {
            body["access_token"] = json!(token(&claims(SOURCE), algorithm, KEY))
        });
        change_body(&options, false, |body| {
            body["access_token"] = json!(token(&claims(TARGET), algorithm, KEY))
        });
        assert!(assert_recorded_response(options).unwrap().passed);
    }
    for defect in [
        "random_overlap",
        "ancestor_overlap",
        "duplicate",
        "dynamic_claim",
        "tolerance",
        "literal_key",
    ] {
        let (_temp, options, feedback) = fixture();
        install_jwt_fixture(feedback).unwrap();
        let mut policy: Value = fixture_policy_view(&options.policy);
        let rules = &mut policy["response_rules"]["json"]["POST /connector/token"];
        match defect {
            "random_overlap" | "ancestor_overlap" => {
                rules["random"] = json!([{"pointer":if defect=="random_overlap" {"/access_token"} else {""},"source_evidence":"Generator:random","source_example":"a","target_example":"b"}])
            }
            "duplicate" => rules["jwt"] = json!([rules["jwt"][0].clone(), rules["jwt"][0].clone()]),
            "dynamic_claim" => rules["jwt"][0]["dynamic_claims"] = json!(["/sub"]),
            "tolerance" => rules["jwt"][0]["tolerance"] = json!("10s"),
            "literal_key" => {
                rules["jwt"][0]["signing_key_source"] = json!({"kind":"literal","value":KEY})
            }
            _ => unreachable!(),
        }
        let written = crate::replay::write_policy_fixture(
            &options.policy,
            serde_yaml::to_string(&policy).unwrap(),
        );
        assert!(
            written.is_err() || load_replay_policy(&options.policy).is_err(),
            "{defect}"
        );
    }
}

#[test]
fn response_jwt_rejects_duplicate_claims_and_headers_and_missing_signing_input() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac};
    for defect in ["claims", "header", "key"] {
        let (temp, options, feedback) = fixture();
        install_jwt_fixture(feedback).unwrap();
        if defect == "key" {
            fs::remove_file(temp.path().join(".traffic-e2e/local/target.env")).unwrap();
        } else {
            let header = if defect == "header" {
                r#"{"alg":"HS256","alg":"HS256","typ":"JWT"}"#
            } else {
                r#"{"alg":"HS256","typ":"JWT"}"#
            };
            let payload = if defect == "claims" {
                format!(r#"{{"sub":"user","sub":"admin","exp":{}}}"#, TARGET + 1800)
            } else {
                claims(TARGET).to_string()
            };
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header),
                URL_SAFE_NO_PAD.encode(payload)
            );
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(KEY.as_bytes()).unwrap();
            mac.update(input.as_bytes());
            let signed = format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
            );
            change_body(&options, false, |body| body["access_token"] = json!(signed));
        }
        let report = assert_recorded_response(options).unwrap();
        assert_eq!(
            report.differences[0].kind,
            if defect == "key" {
                ResponseDifferenceKind::JwtSigningKeyUnavailable
            } else {
                ResponseDifferenceKind::JwtInvalid
            }
        );
    }
}

#[tokio::test]
async fn response_jwt_verifies_a_fresh_token_issued_over_http() {
    use http_body_util::{BodyExt as _, Full};
    use hyper::{Request, Response, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let (_temp, options, feedback) = fixture();
    install_jwt_fixture(feedback).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket),service_fn(|_| async {
            let current=chrono::Utc::now().timestamp();
            Ok::<_,std::convert::Infallible>(Response::new(Full::new(bytes::Bytes::from(
                json!({"access_token":token(&claims(current),Algorithm::HS256,KEY),"token_type":"bearer"}).to_string()))))
        })).await.unwrap();
    });
    let sent_at = chrono::Utc::now();
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .build_http::<Full<bytes::Bytes>>();
    let request = Request::post(format!("http://{address}/connector/token"))
        .header("connection", "close")
        .body(Full::new(bytes::Bytes::new()))
        .unwrap();
    let response = client.request(request).await.unwrap();
    let status = response.status().as_u16();
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    write(
        &options.actual_response,
        &json!({"version":1,"status":status,"request_sent_at":sent_at,
        "body":{"encoding":"utf8","data":body,"truncated":false}}),
    );
    server.await.unwrap();
    let report = assert_recorded_response(options).unwrap();
    assert!(report.passed, "{:?}", report.differences);
}
