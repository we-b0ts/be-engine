use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

fn signed(time: i64, change: impl FnOnce(&mut Value), kid: &str) -> String {
    let mut claims = claims(time);
    change(&mut claims);
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_der(&STANDARD.decode(super::keys::PRIVATE_DER).unwrap()),
    )
    .unwrap()
}

fn refresh(options: &ResponseAssertionOptions, feedback: &ResponseJwtRuleFeedback) {
    let report = assert_recorded_response(copy(options)).unwrap();
    let ResponseBodyRuleEvidence::FocusedE2e {
        assertion_report, ..
    } = &feedback.evidence;
    let mut summary: Value = serde_json::from_slice(&fs::read(assertion_report).unwrap()).unwrap();
    let detail = summary["cases"][0]["response"]["detail_report"]
        .as_str()
        .unwrap();
    let bytes = serde_json::to_vec(&report).unwrap();
    fs::write(detail, &bytes).unwrap();
    summary["policy_fingerprint"] = json!(report.policy_fingerprint);
    summary["cases"][0]["response"]["detail_fingerprint"] = json!(fingerprint(&bytes));
    write(assertion_report, &summary);
}

fn rsa_fixture() -> (
    tempfile::TempDir,
    ResponseAssertionOptions,
    ResponseJwtRuleFeedback,
) {
    let (temp, options, mut feedback) = fixture();
    for (expected, time) in [(true, SOURCE), (false, TARGET)] {
        change_body(
            &options,
            expected,
            |body| *body = json!({"access_token":signed(time, |_| {},"key-1"),"token_type":"bearer","issued_at":time,"expires_at":time+1800,"expires_in":1800}),
        );
    }
    let dependency = json!({"event_type":"mysql_exchange","target_host":"db.internal","target_port":3306,"database":"app","command":"COM_QUERY","sql":"SELECT document FROM signing_keys WHERE id = 7","params":[],"parse_warnings":[],"outcome":"response","response":{"status":"resultset","columns":[{"name":"document","family":"string","sql_type":"JSON"}],"rows":[[{"kind":"json","value":json!({"spec":{"publicKeyPem":super::keys::PUBLIC_PEM,"kid":"key-1","algorithm":"RS256"}}).to_string()}]],"rows_truncated":false}});
    write(&temp.path().join("dependencies.jsonl"), &dependency);
    feedback.rules[0] = serde_json::from_value(json!({"pointer":"/access_token","algorithm":"RS256","signing_key_source":{"kind":"recorded_mysql","host":"db.internal","port":3306,"database":"app","sql":"SELECT document FROM signing_keys WHERE id = ?","params":[7],"column":"document","json_pointer":"/spec/publicKeyPem","kid_pointer":"/spec/kid","algorithm_pointer":"/spec/algorithm","kid":"key-1"},"expires_at":"/expires_at","expires_at_format":"unix_seconds","issued_at":"/issued_at","ttl":"/expires_in","source_evidence":"issue signs iat and exp=iat+ttl with an issuer RSA key"})).unwrap();
    refresh(&options, &feedback);
    (temp, options, feedback)
}

#[test]
fn response_jwt_rs256_recorded_public_key_and_integer_companions_plan_apply_replay() {
    let (_temp, options, feedback) = rsa_fixture();
    let expected = fs::read(&options.expected_response).unwrap();
    let dependencies = fs::read(options.request.with_file_name("dependencies.jsonl")).unwrap();
    install_jwt_fixture(feedback).unwrap();
    let report = assert_recorded_response(copy(&options)).unwrap();
    assert!(report.passed, "{:?}", report.differences);
    assert_eq!(expected, fs::read(&options.expected_response).unwrap());
    assert_eq!(
        dependencies,
        fs::read(options.request.with_file_name("dependencies.jsonl")).unwrap()
    );
}

#[test]
fn response_jwt_rs256_rejects_signature_identity_algorithm_and_time_defects() {
    for defect in [
        "target_signature",
        "source_signature",
        "claims",
        "kid",
        "lifetime",
        "old",
        "algorithm",
        "expires_at",
        "issued_at",
        "ttl",
        "fractional_expiry",
        "missing_expiry",
        "missing_iat",
    ] {
        let (_temp, options, feedback) = rsa_fixture();
        install_jwt_fixture(feedback).unwrap();
        change_body(
            &options,
            defect == "source_signature",
            |body| match defect {
                "target_signature" | "source_signature" => {
                    let mut token = body["access_token"].as_str().unwrap().to_string();
                    let i = token.rfind('.').unwrap() + 1;
                    token.replace_range(i..i + 1, if &token[i..i + 1] == "A" { "B" } else { "A" });
                    body["access_token"] = json!(token);
                }
                "claims" => {
                    body["access_token"] =
                        json!(signed(TARGET, |c| c["roles"] = json!(["admin"]), "key-1"))
                }
                "kid" => body["access_token"] = json!(signed(TARGET, |_| {}, "key-2")),
                "lifetime" => {
                    body["access_token"] =
                        json!(signed(TARGET, |c| c["exp"] = json!(TARGET + 1806), "key-1"))
                }
                "missing_iat" => {
                    body["access_token"] = json!(signed(
                        TARGET,
                        |c| {
                            c.as_object_mut().unwrap().remove("iat");
                        },
                        "key-1"
                    ))
                }
                "old" => body["access_token"] = json!(signed(SOURCE, |_| {}, "key-1")),
                "algorithm" => {
                    body["access_token"] = json!(token(
                        &claims(TARGET),
                        Algorithm::HS256,
                        super::keys::PUBLIC_PEM
                    ))
                }
                "expires_at" => body["expires_at"] = json!(TARGET + 1801),
                "issued_at" => body["issued_at"] = json!(TARGET + 1),
                "ttl" => body["expires_in"] = json!(1801),
                "fractional_expiry" => body["expires_at"] = json!(TARGET as f64 + 1800.5),
                "missing_expiry" => {
                    body.as_object_mut().unwrap().remove("expires_at");
                }
                _ => unreachable!(),
            },
        );
        let report = assert_recorded_response(options).unwrap();
        assert!(!report.passed, "{defect}");
    }
}

#[test]
fn response_jwt_rs256_key_selectors_fail_closed_and_freeze_dependencies() {
    for defect in [
        "missing",
        "ambiguous",
        "params",
        "host",
        "column",
        "truncated",
        "kid",
        "algorithm",
        "malformed_key",
        "after_plan",
    ] {
        let (temp, options, mut feedback) = rsa_fixture();
        let path = temp.path().join("dependencies.jsonl");
        install_jwt_fixture(feedback.clone()).unwrap();
        let installed_policy = fs::read(&options.policy).unwrap();
        let compiled = crate::policy::compile_policy(
            &crate::policy::parse_policy(&fs::read_to_string(&options.policy).unwrap()).unwrap(),
        )
        .unwrap();
        let frozen = crate::primary_protocol::assertion::native::NativeResponseContext::load(
            &compiled,
            "POST",
            "/connector/token",
            None,
            temp.path(),
            temp.path(),
        )
        .unwrap();
        let mut event: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match defect {
            "missing" => event["sql"] = json!("SELECT document FROM signing_keys WHERE id = 8"),
            "params" => {
                if let crate::ResponseJwtKeySource::RecordedMysql { params, .. } =
                    &mut feedback.rules[0].signing_key_source
                {
                    *params = vec![json!(8)];
                }
            }
            "host" => event["target_host"] = json!("other.internal"),
            "column" => event["response"]["columns"][0]["name"] = json!("other"),
            "truncated" => event["response"]["rows_truncated"] = json!(true),
            "kid" | "algorithm" | "malformed_key" | "after_plan" => {
                let mut document: Value = serde_json::from_str(
                    event["response"]["rows"][0][0]["value"].as_str().unwrap(),
                )
                .unwrap();
                match defect {
                    "kid" => document["spec"]["kid"] = json!("key-2"),
                    "algorithm" => document["spec"]["algorithm"] = json!("HS256"),
                    _ => document["spec"]["publicKeyPem"] = json!("invalid"),
                }
                event["response"]["rows"][0][0]["value"] = json!(document.to_string());
            }
            _ => (),
        }
        if defect == "ambiguous" {
            fs::write(&path, format!("{event}\n{event}\n")).unwrap();
        } else {
            write(&path, &event);
        }
        if defect == "after_plan" {
            assert!(frozen.ensure_current().is_err());
        }
        if defect == "params" {
            install_jwt_fixture(feedback).unwrap();
        }
        if let Ok(report) = assert_recorded_response(copy(&options)) {
            assert!(!report.passed, "{defect}");
            assert!(
                report.differences.iter().any(|difference| difference.kind
                    == ResponseDifferenceKind::JwtSigningKeyUnavailable),
                "{defect}"
            );
        }
        if defect != "params" {
            assert_eq!(fs::read(&options.policy).unwrap(), installed_policy);
        }
    }
}

#[test]
fn response_jwt_rs256_planner_rejects_bad_signature_before_writing_policy() {
    let (_temp, options, feedback) = rsa_fixture();
    let policy = fs::read(&options.policy).unwrap();
    change_body(&options, false, |body| {
        body["access_token"] = json!(token(
            &claims(TARGET),
            Algorithm::HS256,
            super::keys::PUBLIC_PEM
        ));
    });
    refresh(&options, &feedback);
    let error = plan_response_jwt_rule(feedback).err().unwrap().to_string();
    assert!(
        error.contains("legacy rule authoring is retired"),
        "{error}"
    );
    assert_eq!(policy, fs::read(&options.policy).unwrap());
}

#[test]
fn response_jwt_rs256_supports_prepared_key_reads_and_keeps_ttl_exact() {
    let (temp, options, feedback) = rsa_fixture();
    let path = temp.path().join("dependencies.jsonl");
    let mut event: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    event["command"] = json!("COM_STMT_EXECUTE");
    event["sql"] = json!("SELECT document FROM signing_keys WHERE id = ?");
    event["params"] = json!([{"kind":"integer","value":7}]);
    write(&path, &event);
    install_jwt_fixture(feedback).unwrap();
    assert!(assert_recorded_response(copy(&options)).unwrap().passed);
    change_body(&options, false, |body| {
        body["access_token"] = json!(signed(
            TARGET,
            |claims| claims["exp"] = json!(TARGET + 1801),
            "key-1"
        ));
        body["expires_at"] = json!(TARGET + 1801);
        body["expires_in"] = json!(1801);
    });
    let report = assert_recorded_response(options).unwrap();
    assert!(!report.passed);
    assert!(
        report
            .differences
            .iter()
            .any(|d| d.pointer == "/expires_in")
    );
    assert!(
        !report
            .differences
            .iter()
            .any(|d| d.pointer == "/access_token")
    );
}

#[test]
fn response_jwt_rs256_companions_follow_wildcard_item_scope() {
    let (_temp, options, mut feedback) = rsa_fixture();
    for (expected, time) in [(true, SOURCE), (false, TARGET)] {
        change_body(
            &options,
            expected,
            |body| *body = json!({"items":[{"token":signed(time, |_| {},"key-1"),"issued":time,"expiry":time+1800,"ttl":1800},{"token":signed(time+1, |_| {},"key-1"),"issued":time+1,"expiry":time+1801,"ttl":1800}]}),
        );
    }
    let rule = &mut feedback.rules[0];
    rule.pointer = "/items/*/token".into();
    rule.issued_at = Some("/items/*/issued".into());
    rule.expires_at = Some("/items/*/expiry".into());
    rule.ttl = Some("/items/*/ttl".into());
    refresh(&options, &feedback);
    install_jwt_fixture(feedback).unwrap();
    assert!(assert_recorded_response(copy(&options)).unwrap().passed);
    change_body(&options, false, |body| {
        body["items"][1]["expiry"] = json!(TARGET + 1800)
    });
    assert!(!assert_recorded_response(options).unwrap().passed);
}
