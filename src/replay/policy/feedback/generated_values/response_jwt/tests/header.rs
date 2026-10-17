//! A Location JWT uses the same signature/nonce kernel as a JSON URL carrier.
use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

fn location(time: i64, byte: u8, key: &str) -> String {
    let nonce = URL_SAFE_NO_PAD.encode([byte; 32]);
    let mut value = claims(time);
    value["nonce"] = json!(nonce);
    format!(
        "https://issuer.test/auth?client_id=app&state={}&nonce={nonce}&scope=openid#keep",
        token(&value, Algorithm::HS256, key)
    )
}

fn install(options: &ResponseAssertionOptions, header: bool) {
    let select = if header {
        json!({"location":{"header":"Location"}})
    } else {
        json!({"pointer":"/auth_url"})
    };
    let mut effect = json!({"kind":"response_jwt","url_query_param":"state","algorithm":"HS256",
        "signing_key":{"kind":"startup","source":{"kind":"target_env","name":"SECRET_KEY"}},
        "nonces":[{"pointer":"/nonce","format":{"kind":"base64url","decoded_bytes":32},"echo_query_param":"nonce"}]});
    effect
        .as_object_mut()
        .unwrap()
        .extend(select.as_object().unwrap().clone());
    let policy = json!({"format":"traffic-policy/v1","rules":[{"id":"oidc-state","match":{"api":"POST /connector/token"},"effect":effect,
        "proof":{"source":"oidc.py:login","fact":"Source signs state and repeats the signed nonce in the authorization URL"}}]});
    fs::write(&options.policy, serde_yaml::to_string(&policy).unwrap()).unwrap();
}

fn response(options: &ResponseAssertionOptions, source: bool, url: &str, header: bool) {
    let time = if source { SOURCE } else { TARGET };
    let mut value = json!({"version":1,"status":307,"request_sent_at":chrono::DateTime::from_timestamp(time,0).unwrap(),
        "headers":{"content-type":["text/plain"]},"body":{"encoding":"utf8","data":"","truncated":false}});
    if header {
        value["headers"]["location"] = json!([url]);
    } else {
        value["body"]["data"] = json!(json!({"auth_url":url,"stable":7}).to_string());
    }
    write(
        if source {
            &options.expected_response
        } else {
            &options.actual_response
        },
        &value,
    );
}

#[test]
fn header_jwt_checks_signatures_echoes_complete_urls_clocks_and_multiplicity() {
    let (_temp, options, _) = fixture();
    install(&options, true);
    let source = location(SOURCE, 1, KEY);
    let target = location(TARGET, 2, KEY);
    response(&options, true, &source, true);
    response(&options, false, &target, true);
    let original = fs::read(&options.expected_response).unwrap();
    let report = assert_recorded_response(copy(&options)).unwrap();
    assert!(report.passed, "{:?}", report.differences);
    assert_eq!(report.applied_header_rule_ids, vec!["oidc-state"]);
    assert_eq!(report.body_codec, crate::ResponseBodyCodec::ExactBytes);
    let selected = crate::request_rules::jwt::url_query::select(&target, "state").unwrap();
    let mut altered = claims(TARGET);
    altered["nonce"] = json!(URL_SAFE_NO_PAD.encode([2; 32]));
    altered["exp"] = json!(TARGET + 1801);
    let changed_lifetime = format!(
        "{}{}{}",
        selected.prefix,
        token(&altered, Algorithm::HS256, KEY),
        selected.suffix
    );
    for bad in [
        changed_lifetime,
        target.replace("client_id=app", "client_id=other"),
        target.replace("scope=openid", "scope=admin"),
        target.replace("#keep", "#changed"),
        target.replace(
            &format!("nonce={}", URL_SAFE_NO_PAD.encode([2; 32])),
            &format!("nonce={}", URL_SAFE_NO_PAD.encode([3; 32])),
        ),
        format!("{target}&nonce=duplicate"),
        target.replace("&nonce=", "&nonce=%ZZ"),
        target.replace("&nonce=", "&other="),
        target.replace("&nonce=", "&state=duplicate&nonce="),
        location(TARGET, 2, "wrong-signing-key"),
        location(TARGET - 10, 2, KEY),
    ] {
        response(&options, false, &bad, true);
        assert!(!assert_recorded_response(copy(&options)).unwrap().passed);
    }
    response(&options, false, &target, true);
    let mut actual: Value =
        serde_json::from_slice(&fs::read(&options.actual_response).unwrap()).unwrap();
    for field in ["duplicate", "absent", "body", "status"] {
        let mut changed = actual.clone();
        match field {
            "duplicate" => changed["headers"]["location"] = json!([target, target]),
            "absent" => {
                changed["headers"]
                    .as_object_mut()
                    .unwrap()
                    .remove("location");
            }
            "body" => changed["body"]["data"] = json!("unexpected"),
            _ => changed["status"] = json!(200),
        }
        write(&options.actual_response, &changed);
        assert!(
            !assert_recorded_response(copy(&options)).unwrap().passed,
            "{field}"
        );
    }
    actual["headers"]["location"] = json!([target]);
    write(&options.actual_response, &actual);
    fs::write(
        options.policy.parent().unwrap().join("local/target.env"),
        "SECRET_KEY=changed\n",
    )
    .unwrap();
    assert!(!assert_recorded_response(copy(&options)).unwrap().passed);
    assert_eq!(fs::read(&options.expected_response).unwrap(), original);
}

#[test]
fn body_url_reuses_nonce_echo_validation_and_header_candidates_are_payload_free() {
    let (_temp, options, _) = fixture();
    install(&options, false);
    response(&options, true, &location(SOURCE, 1, KEY), false);
    response(&options, false, &location(TARGET, 2, KEY), false);
    assert!(assert_recorded_response(copy(&options)).unwrap().passed);
    fs::write(&options.policy, "format: traffic-policy/v1\nrules: []\n").unwrap();
    response(&options, true, &location(SOURCE, 1, KEY), true);
    response(&options, false, &location(TARGET, 2, KEY), true);
    let report = assert_recorded_response(copy(&options)).unwrap();
    assert_eq!(
        serde_json::to_value(&report.header_jwt_candidates).unwrap(),
        json!([{"header":"location","jwt_candidate":true}])
    );
    let public = serde_json::to_string(&report.header_jwt_candidates).unwrap();
    assert!(!public.contains("eyJ") && !public.contains(KEY));
}
