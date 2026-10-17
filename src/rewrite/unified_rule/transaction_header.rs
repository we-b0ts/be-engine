//! Header JWTs retain the public evidence/plan/apply and frozen-key transaction.
use super::*;

const KEY: &str = "header-plan-signing-key";
fn location(time: i64, nonce: &str, key: &str) -> String {
    let claims = json!({"iat":time,"exp":time+600,"nonce":nonce,"redirect":"/home"});
    let token = crate::request_rules::tests::token(claims, key);
    format!("https://issuer.test/auth?state={token}&nonce={nonce}&scope=openid")
}

fn responses(fixture: &Fixture, bad_key: bool) {
    fixture.replace_response_bodies(b"", b"");
    let mut assertions: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.paths.assertions).unwrap()).unwrap();
    let summary = &mut assertions["cases"][0]["response"];
    let source = PathBuf::from(summary["expected_response"].as_str().unwrap());
    let target = PathBuf::from(summary["actual_response"].as_str().unwrap());
    let time = chrono::DateTime::parse_from_rfc3339("2026-10-16T00:00:00Z")
        .unwrap()
        .timestamp();
    for (path, time, nonce, key) in [
        (&source, time, "11111111-1111-4111-8111-111111111111", KEY),
        (
            &target,
            time + 60,
            "22222222-2222-4222-8222-222222222222",
            if bad_key { "wrong-key" } else { KEY },
        ),
    ] {
        let mut response: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        response["headers"] = json!({"location":[location(time,nonce,key)]});
        write(path, response);
    }
    let detail = PathBuf::from(summary["detail_report"].as_str().unwrap());
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&detail).unwrap()).unwrap();
    value["expected_response_fingerprint"] = json!(crate::verification_progress::fingerprint(
        &fs::read(source).unwrap()
    ));
    value["actual_response_fingerprint"] = json!(crate::verification_progress::fingerprint(
        &fs::read(target).unwrap()
    ));
    write(&detail, value);
    summary["detail_fingerprint"] = json!(crate::verification_progress::fingerprint(
        &fs::read(detail).unwrap()
    ));
    let state_path = fixture
        .paths
        .replay
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("state.yaml");
    let mut focused: serde_json::Value =
        serde_yaml::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
    focused["cases"][0]["response_assertion"] = summary.clone();
    fs::write(state_path, serde_yaml::to_string(&focused).unwrap()).unwrap();
    write(&fixture.paths.assertions, assertions);
}

#[test]
fn header_jwt_public_plan_apply_validates_both_original_signatures_and_freezes_keys() {
    for scenario in ["apply", "bad-signature", "changed-key"] {
        let fixture = Fixture::new();
        let keyfile = fixture.target.path().join(".traffic-e2e/local/target.env");
        fs::write(&keyfile, format!("SECRET_KEY={KEY}\n")).unwrap();
        let mut state = fixture.state();
        state.replay_identity = Some(fingerprint::replay_identity(fixture.target.path()).unwrap());
        fixture.store().save(&state).unwrap();
        responses(&fixture, scenario == "bad-signature");
        write(
            &fixture.proposal,
            json!({"id":"login-state","match":{"api":"GET /api"},
            "effect":{"kind":"response_jwt","location":{"header":"location"},"url_query_param":"state","algorithm":"HS256",
                "signing_key":{"kind":"startup","source":{"kind":"target_env","name":"SECRET_KEY"}},
                "nonces":[{"pointer":"/nonce","format":{"kind":"uuid_v4"},"echo_query_param":"nonce"}]},
            "proof":{"source":"oidc.py:login","fact":"Source signs a fresh state nonce and echoes it in the query"}}),
        );
        fixture.confirm();
        let plan = fixture.plan();
        if scenario == "bad-signature" {
            assert!(plan.is_err());
            continue;
        }
        let plan = plan.unwrap();
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["source_validations"],
            1
        );
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["independent_target_validations"],
            1
        );
        let public = serde_json::to_string(&plan.traffic_e2e_report).unwrap();
        assert!(!public.contains(KEY) && !public.contains("eyJ"));
        if scenario == "changed-key" {
            fs::write(keyfile, "SECRET_KEY=changed\n").unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
        } else {
            apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
        }
    }
}
