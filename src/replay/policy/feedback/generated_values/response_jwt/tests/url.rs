//! Signed download descriptors, tested through the real response planner/assertion boundary.
use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

fn nonce(byte: u8) -> String {
    URL_SAFE_NO_PAD.encode([byte; 16])
}

fn descriptor(time: i64, nonce: &str) -> Value {
    let mut value = claims(time);
    value["smart_app_id"] = json!(7);
    value["release_id"] = json!(9);
    value["user_id"] = json!(11);
    value["purpose"] = json!("smart_app_artifact_download");
    value["nonce"] = json!(nonce);
    let signed = token(&value, Algorithm::HS256, KEY);
    json!({
        "downloadUrl":format!("/api/smart-apps/marketplace/7/artifact?download=1&token={signed}&filename=a%2Fb#content"),
        "expiresAt":chrono::DateTime::from_timestamp(time+1800,123_456_000).unwrap().to_rfc3339(),
        "sha256":"stable-package-digest", "releaseId":9,
    })
}

fn refresh_evidence(options: &ResponseAssertionOptions, feedback: &ResponseJwtRuleFeedback) {
    let report = assert_recorded_response(copy(options)).unwrap();
    let ResponseBodyRuleEvidence::FocusedE2e {
        assertion_report, ..
    } = &feedback.evidence;
    let mut index: Value = serde_json::from_slice(&fs::read(assertion_report).unwrap()).unwrap();
    let detail = PathBuf::from(
        index["cases"][0]["response"]["detail_report"]
            .as_str()
            .unwrap(),
    );
    let bytes = serde_json::to_vec(&report).unwrap();
    fs::write(detail, &bytes).unwrap();
    index["cases"][0]["response"]["detail_fingerprint"] = json!(fingerprint(&bytes));
    write(assertion_report, &index);
}

fn url_fixture() -> (
    tempfile::TempDir,
    ResponseAssertionOptions,
    ResponseJwtRuleFeedback,
) {
    let (temp, options, mut feedback) = fixture();
    feedback.rules = vec![serde_json::from_value(json!({
        "pointer":"/downloadUrl", "url_query_param":"token", "expires_at":"/expiresAt",
        "algorithm":"HS256", "signing_key_source":{"kind":"target_env","name":"SECRET_KEY"},
        "dynamic_claims":[{"pointer":"/nonce","format":"base64url","decoded_bytes":16}],
        "source_evidence":"Download:descriptor signs scoped identity and a token_urlsafe(16) nonce; expiresAt is the same expiry datetime"
    })).unwrap()];
    change_body(&options, true, |body| *body = descriptor(SOURCE, &nonce(1)));
    change_body(&options, false, |body| {
        *body = descriptor(TARGET, &nonce(2))
    });
    refresh_evidence(&options, &feedback);
    (temp, options, feedback)
}

fn change_token(body: &mut Value, edit: impl FnOnce(&mut Value), key: &str) {
    let raw = body["downloadUrl"].as_str().unwrap();
    let selected = crate::request_rules::jwt::url_query::select(raw, "token").unwrap();
    let mut parsed = crate::request_rules::jwt::Token::parse(&selected.token)
        .unwrap()
        .unwrap()
        .claims;
    edit(&mut parsed);
    body["downloadUrl"] = json!(format!(
        "{}{}{}",
        selected.prefix,
        token(&parsed, Algorithm::HS256, key),
        selected.suffix
    ));
}

#[test]
fn response_jwt_url_plan_apply_owns_expiry_and_preserves_evidence() {
    let (_temp, options, feedback) = url_fixture();
    let original = fs::read(&options.expected_response).unwrap();
    install_jwt_fixture(feedback).unwrap();
    assert_eq!(fs::read(&options.expected_response).unwrap(), original);
    let report = assert_recorded_response(copy(&options)).unwrap();
    assert!(report.passed, "{:?}", report.differences);
    assert_eq!(report.applied_body_rule_ids.len(), 1);
    change_body(&options, false, |body| {
        body["sha256"] = json!("wrong-package")
    });
    assert!(!assert_recorded_response(options).unwrap().passed);
}

#[test]
fn jwt_companion_keeps_request_relation_while_other_business_times_use_response_completion() {
    let (_temp, options, feedback) = url_fixture();
    install_jwt_fixture(feedback).unwrap();
    let at = |seconds| {
        chrono::DateTime::from_timestamp(seconds, 0)
            .unwrap()
            .to_rfc3339()
    };
    for (source, seconds, path, clock) in [
        (true, SOURCE + 30, &options.expected_response, "timestamp"),
        (
            false,
            TARGET + 90,
            &options.actual_response,
            "response_completed_at",
        ),
    ] {
        change_body(&options, source, |body| {
            body["createdAt"] = json!(at(seconds))
        });
        let mut response: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        response[clock] = json!(at(seconds));
        write(path, &response);
    }
    let passed = assert_recorded_response(copy(&options)).unwrap();
    assert!(passed.passed, "{:?}", passed.differences);
    change_body(&options, false, |body| {
        body["createdAt"] = json!(at(TARGET + 30))
    });
    let rejected = assert_recorded_response(options).unwrap();
    assert!(!rejected.passed);
    assert!(
        rejected
            .differences
            .iter()
            .any(|difference| difference.pointer == "/createdAt")
    );
}

#[test]
fn response_jwt_url_rejects_unselected_url_changes_and_ambiguous_tokens() {
    for defect in [
        "path",
        "host",
        "query",
        "fragment",
        "extra",
        "duplicate",
        "encoded_duplicate",
        "empty",
        "missing",
        "fragment_only",
        "percent",
        "malformed",
        "scheme",
        "type",
    ] {
        let (_temp, options, feedback) = url_fixture();
        install_jwt_fixture(feedback).unwrap();
        change_body(&options, false, |body| {
            let raw = body["downloadUrl"].as_str().unwrap();
            let altered = match defect {
                "path" => raw.replacen("/7/", "/8/", 1),
                "host" => format!("https://other.example{raw}"),
                "query" => raw.replace("a%2Fb", "a/b"),
                "fragment" => raw.replace("#content", "#different"),
                "extra" => raw.replace("#content", "&added=1#content"),
                "duplicate" => raw.replace("#content", "&token=second#content"),
                "encoded_duplicate" => raw.replace("#content", "&%74oken=second#content"),
                "empty" => "/api/download?token=".into(),
                "missing" => "/api/download?other=value".into(),
                "fragment_only" => "/api/download#fragment?token=value".into(),
                "percent" => raw.replace("filename=a%2Fb", "filename=%XX"),
                "malformed" => raw.replace("token=", "token=invalid."),
                "scheme" => "javascript:alert(1)?token=value".into(),
                "type" => String::new(),
                _ => unreachable!(),
            };
            body["downloadUrl"] = if defect == "type" {
                Value::Null
            } else {
                json!(altered)
            };
        });
        let report = assert_recorded_response(options).unwrap();
        assert!(!report.passed, "{defect}");
        assert!(
            report.differences.iter().any(|d| matches!(
                d.kind,
                ResponseDifferenceKind::JwtInvalid | ResponseDifferenceKind::JwtUrlMismatch
            )),
            "{defect}: {:?}",
            report.differences
        );
    }
}

#[test]
fn response_jwt_url_checks_nonce_signature_stable_claims_and_time() {
    for defect in [
        "length",
        "padding",
        "alphabet",
        "trailing_bits",
        "missing_nonce",
        "nonce_type",
        "signature",
        "identity",
        "purpose",
        "lifetime",
        "old_token",
        "missing_exp",
    ] {
        let (_temp, options, feedback) = url_fixture();
        install_jwt_fixture(feedback).unwrap();
        change_body(&options, false, |body| {
            change_token(
                body,
                |value| match defect {
                    "length" => value["nonce"] = json!(URL_SAFE_NO_PAD.encode([1; 15])),
                    "padding" => value["nonce"] = json!(format!("{}==", nonce(2))),
                    "alphabet" => value["nonce"] = json!("++++++++++++++++++++++"),
                    "trailing_bits" => value["nonce"] = json!(format!("{}h", &nonce(2)[..21])),
                    "missing_nonce" => {
                        value.as_object_mut().unwrap().remove("nonce");
                    }
                    "nonce_type" => value["nonce"] = json!(42),
                    "identity" => value["user_id"] = json!(12),
                    "purpose" => value["purpose"] = json!("other-purpose"),
                    "lifetime" => value["exp"] = json!(TARGET + 1806),
                    "old_token" => {
                        value["iat"] = json!(SOURCE);
                        value["exp"] = json!(SOURCE + 1800);
                    }
                    "missing_exp" => {
                        value.as_object_mut().unwrap().remove("exp");
                    }
                    "signature" => (),
                    _ => unreachable!(),
                },
                if defect == "signature" {
                    "wrong-key"
                } else {
                    KEY
                },
            );
        });
        assert!(
            !assert_recorded_response(options).unwrap().passed,
            "{defect}"
        );
    }
}

#[test]
fn response_jwt_expiry_is_bound_to_each_own_token_at_integer_second_precision() {
    for side in [false, true] {
        for defect in ["shift", "malformed", "number", "missing"] {
            let (_temp, options, feedback) = url_fixture();
            install_jwt_fixture(feedback).unwrap();
            change_body(&options, side, |body| match defect {
                "shift" => {
                    body["expiresAt"] = json!(
                        chrono::DateTime::from_timestamp(
                            if side { SOURCE + 1802 } else { TARGET + 1802 },
                            0
                        )
                        .unwrap()
                        .to_rfc3339()
                    )
                }
                "malformed" => body["expiresAt"] = json!("tomorrow"),
                "number" => body["expiresAt"] = json!(TARGET + 1800),
                "missing" => {
                    body.as_object_mut().unwrap().remove("expiresAt");
                }
                _ => unreachable!(),
            });
            let report = assert_recorded_response(options).unwrap();
            assert!(
                report.differences.iter().any(|d| d.kind
                    == ResponseDifferenceKind::JwtExpiryMismatch
                    || defect == "missing"
                        && matches!(
                            d.kind,
                            ResponseDifferenceKind::ValueMismatch
                                | ResponseDifferenceKind::MissingActual
                                | ResponseDifferenceKind::UnexpectedActual
                        )),
                "{side} {defect}"
            );
        }
    }
    let (_temp, options, feedback) = url_fixture();
    install_jwt_fixture(feedback).unwrap();
    change_body(&options, false, |body| {
        let value = chrono::DateTime::from_timestamp(TARGET + 1800, 999_999_000).unwrap();
        body["expiresAt"] = json!(value.to_rfc3339());
        body["downloadUrl"] = json!(body["downloadUrl"].as_str().unwrap().replace('.', "%2E"));
    });
    assert!(assert_recorded_response(options).unwrap().passed);
}

#[test]
fn response_jwt_expiry_retains_source_fraction_width_and_timezone_spelling() {
    for defect in ["none", "precision", "zone"] {
        let (_temp, options, feedback) = url_fixture();
        install_jwt_fixture(feedback).unwrap();
        change_body(&options, true, |body| {
            body["expiresAt"] = json!(
                chrono::DateTime::from_timestamp(SOURCE + 1800, 0)
                    .unwrap()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            );
        });
        change_body(&options, false, |body| {
            body["expiresAt"] = json!(
                chrono::DateTime::from_timestamp(
                    TARGET + 1800,
                    if defect == "precision" {
                        123_000_000
                    } else {
                        0
                    },
                )
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, defect != "zone")
            );
        });
        let report = assert_recorded_response(options).unwrap();
        assert_eq!(
            report.passed,
            defect == "none",
            "{defect}: {:?}",
            report.differences
        );
        if defect != "none" {
            assert!(
                report
                    .differences
                    .iter()
                    .any(|difference| difference.kind == ResponseDifferenceKind::JwtExpiryMismatch)
            );
        }
    }
}

#[test]
fn response_jwt_url_rejects_invalid_signed_inputs_and_expiry_without_mutating_source() {
    for source in [true, false] {
        let (_temp, options, feedback) = url_fixture();
        install_jwt_fixture(feedback).unwrap();
        change_body(&options, source, |body| {
            change_token(body, |_| (), "wrong-key")
        });
        assert!(!assert_recorded_response(options).unwrap().passed);
    }
    let (_temp, options, feedback) = url_fixture();
    install_jwt_fixture(feedback).unwrap();
    let original = fs::read(&options.expected_response).unwrap();
    change_body(&options, false, |body| {
        body["expiresAt"] = json!("2026-01-01T00:00:00Z")
    });
    assert!(!assert_recorded_response(copy(&options)).unwrap().passed);
    assert_eq!(fs::read(&options.expected_response).unwrap(), original);
}

#[test]
fn response_jwt_url_validates_nonce_declarations_and_composite_field_ownership() {
    for defect in [
        "identity",
        "legacy_nonce",
        "missing_size",
        "zero_size",
        "large_size",
        "uuid_size",
        "duplicate_claim",
        "unknown_field",
        "expiry_overlap",
        "expiry_ancestor",
        "expiry_array_scope",
        "query_name",
        "expiry_type",
    ] {
        let (_temp, options, feedback) = url_fixture();
        install_jwt_fixture(feedback).unwrap();
        let mut policy: Value = fixture_policy_view(&options.policy);
        let rules = &mut policy["response_rules"]["json"]["POST /connector/token"];
        let rule = &mut rules["jwt"][0];
        match defect {
            "identity" => rule["dynamic_claims"][0]["pointer"] = json!("/sub"),
            "legacy_nonce" => rule["dynamic_claims"] = json!(["/nonce"]),
            "missing_size" => {
                rule["dynamic_claims"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("decoded_bytes");
            }
            "zero_size" => rule["dynamic_claims"][0]["decoded_bytes"] = json!(0),
            "large_size" => rule["dynamic_claims"][0]["decoded_bytes"] = json!(257),
            "uuid_size" => rule["dynamic_claims"][0]["format"] = json!("uuid_v4"),
            "duplicate_claim" => rule["dynamic_claims"]
                .as_array_mut()
                .unwrap()
                .push(json!({"pointer":"/nonce","format":"base64url","decoded_bytes":16})),
            "unknown_field" => rule["dynamic_claims"][0]["extra"] = json!(true),
            "expiry_overlap" => rule["expires_at"] = json!("/downloadUrl"),
            "expiry_ancestor" => {
                rule["pointer"] = json!("/descriptor/url");
                rule["expires_at"] = json!("/descriptor");
            }
            "expiry_array_scope" => rule["expires_at"] = json!("/items/*/expiresAt"),
            "timestamp_overlap" => {
                rules["timestamp"] = json!([{"pointer":"/expiresAt","format":"rfc3339","source_evidence":"Source:now","source_example":"a","target_example":"b"}])
            }
            "query_name" => rule["url_query_param"] = json!("token&other"),
            "expiry_type" => rule["expires_at"] = json!({"pointer":"/expiresAt"}),
            _ => unreachable!(),
        }
        let installed = crate::replay::write_policy_fixture(
            &options.policy,
            serde_yaml::to_string(&policy).unwrap(),
        );
        assert!(
            installed.is_err() || load_replay_policy(&options.policy).is_err(),
            "{defect}"
        );
    }
}

fn descriptor_array(time: i64, nonce: &str) -> Value {
    let first = descriptor(time, nonce);
    let mut second = descriptor(time, nonce);
    change_token(&mut second, |value| value["exp"] = json!(time + 1801), KEY);
    second["expiresAt"] = json!(
        chrono::DateTime::from_timestamp(time + 1801, 0)
            .unwrap()
            .to_rfc3339()
    );
    json!({"items":[first,second]})
}

#[test]
fn response_jwt_url_wildcards_bind_both_nonce_directions_and_the_same_item_expiry() {
    let (_temp, options, mut feedback) = url_fixture();
    feedback.rules[0].pointer = "/items/*/downloadUrl".into();
    feedback.rules[0].expires_at = Some("/items/*/expiresAt".into());
    change_body(&options, true, |body| {
        *body = descriptor_array(SOURCE, &nonce(1))
    });
    change_body(&options, false, |body| {
        *body = descriptor_array(TARGET, &nonce(2))
    });
    refresh_evidence(&options, &feedback);
    install_jwt_fixture(feedback).unwrap();
    assert!(assert_recorded_response(copy(&options)).unwrap().passed);

    change_body(&options, false, |body| {
        change_token(
            &mut body["items"][1],
            |value| value["nonce"] = json!(nonce(3)),
            KEY,
        )
    });
    let report = assert_recorded_response(copy(&options)).unwrap();
    assert!(
        report
            .differences
            .iter()
            .any(|d| d.kind == ResponseDifferenceKind::JwtNonceMismatch)
    );
    change_body(&options, false, |body| {
        *body = descriptor_array(TARGET, &nonce(2))
    });
    change_body(&options, true, |body| {
        change_token(
            &mut body["items"][1],
            |value| value["nonce"] = json!(nonce(3)),
            KEY,
        )
    });
    let report = assert_recorded_response(copy(&options)).unwrap();
    assert!(
        report
            .differences
            .iter()
            .any(|d| d.kind == ResponseDifferenceKind::JwtNonceMismatch)
    );
    change_body(&options, true, |body| {
        *body = descriptor_array(SOURCE, &nonce(1))
    });
    change_body(&options, false, |body| {
        let first = body["items"][0]["expiresAt"].clone();
        body["items"][0]["expiresAt"] = body["items"][1]["expiresAt"].clone();
        body["items"][1]["expiresAt"] = first;
    });
    let report = assert_recorded_response(options).unwrap();
    assert!(
        report
            .differences
            .iter()
            .any(|d| d.kind == ResponseDifferenceKind::JwtExpiryMismatch)
    );
}

#[test]
fn response_jwt_url_supports_absolute_urls_and_encoded_token_values() {
    let (_temp, options, feedback) = url_fixture();
    for side in [true, false] {
        change_body(&options, side, |body| {
            body["downloadUrl"] = json!(format!(
                "https://downloads.example{}",
                body["downloadUrl"].as_str().unwrap()
            ));
        });
    }
    change_body(&options, false, |body| {
        let selected = crate::request_rules::jwt::url_query::select(
            body["downloadUrl"].as_str().unwrap(),
            "token",
        )
        .unwrap();
        body["downloadUrl"] = json!(format!(
            "{}{}{}",
            selected.prefix,
            selected.token.replace('.', "%2E"),
            selected.suffix
        ));
    });
    refresh_evidence(&options, &feedback);
    install_jwt_fixture(feedback).unwrap();
    let report = assert_recorded_response(options).unwrap();
    assert!(report.passed, "{:?}", report.differences);
}

#[tokio::test]
async fn response_jwt_url_plans_from_http_and_requires_a_fresh_http_response() {
    use http_body_util::{BodyExt as _, Full};
    use hyper::{Request, Response, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let (_temp, options, feedback) = url_fixture();
    let original = fs::read(&options.expected_response).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (socket, _) = listener.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(socket),
                    service_fn(|request: Request<hyper::body::Incoming>| async move {
                        assert_eq!(request.uri().path(), "/connector/token");
                        let nonce = URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes());
                        let body = descriptor(chrono::Utc::now().timestamp(), &nonce);
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                            bytes::Bytes::from(body.to_string()),
                        )))
                    }),
                )
                .await
                .unwrap();
        }
    });
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .build_http::<Full<bytes::Bytes>>();
    for stage in 0..2 {
        let sent_at = chrono::Utc::now();
        let request = Request::post(format!("http://{address}/connector/token"))
            .header("connection", "close")
            .body(Full::new(bytes::Bytes::new()))
            .unwrap();
        let response =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.request(request))
                .await
                .unwrap()
                .unwrap();
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        write(
            &options.actual_response,
            &json!({"version":1,"status":status,"headers":{},
            "request_sent_at":sent_at,"body":{"encoding":"utf8","data":body,"truncated":false}}),
        );
        if stage == 0 {
            refresh_evidence(&options, &feedback);
            install_jwt_fixture(ResponseJwtRuleFeedback {
                policy_path: feedback.policy_path.clone(),
                api: feedback.api.clone(),
                rules: feedback.rules.clone(),
                evidence: feedback.evidence.clone(),
            })
            .unwrap();
        } else {
            let report = assert_recorded_response(copy(&options)).unwrap();
            assert!(report.passed, "{:?}", report.differences);
        }
    }
    server.await.unwrap();
    assert_eq!(fs::read(&options.expected_response).unwrap(), original);
}
