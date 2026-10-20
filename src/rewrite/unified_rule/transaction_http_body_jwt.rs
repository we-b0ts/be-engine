//! Outbound JSON JWT contracts use the public transaction and freeze startup keys.
use super::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

const KEY: &str = "synthetic-outbound-transaction-signing-key";
const NOW: i64 = 1_792_108_801;
const RULE: &str = "chat-signed-fields";

fn token(skill: bool, key: &str) -> String {
    let claims = if skill {
        json!({"sub":"user-17","skill_id":"skill-8","iat":NOW,"exp":NOW+7200})
    } else {
        json!({"sub":"user-17","roles":["reader"],"exp":NOW+3600})
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(key.as_bytes()),
    )
    .unwrap()
}

fn prepare(fixture: &Fixture, invalid_token: Option<bool>) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let env = fixture
        .root()
        .join(crate::repository::LOCAL_TARGET_ENV_PATH);
    fs::write(&env, format!("SECRET_KEY={KEY}\n")).unwrap();
    let case = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/api/case-1");
    let dependencies = case.join("dependencies.jsonl");
    let payload = json!({"model":"stable-model","metadata":{
        "request_id":"a1b2c3d4",
        "auth_token":token(false, if invalid_token == Some(false) { "wrong-key" } else { KEY }),
        "skill_identity_token":token(true, if invalid_token == Some(true) { "wrong-key" } else { KEY }),
        "business_id":17
    }});
    let event = json!({
        "event_type":"http_exchange","id":uuid::Uuid::new_v4(),"scheme":"http",
        "authority":"chat.example.test:80","method":"POST","uri":"/chat?mode=stable",
        "request_headers":{"content-type":["application/json"]},"request_body":body(payload),
        "response_status":200,"response_headers":{"content-type":["application/json"]},
        "response_body":body(json!({"accepted":true})),
        "timestamp":"2026-10-16T00:00:01Z","request_started_at":"2026-10-16T00:00:01Z",
        "duration_ms":0,"outcome":"response","error":null
    });
    fs::write(&dependencies, format!("{event}\n")).unwrap();
    let jwt = json!({"kind":"jwt","algorithm":"HS256",
        "signing_key":{"kind":"target_env","name":"SECRET_KEY"}});
    write(
        &fixture.proposal,
        json!({"id":RULE,"match":{"api":"GET /api",
            "resource":{"protocol":"http","endpoint":"chat.example.test:80"},
            "operation":"POST","path":"/chat"},
            "effect":{"kind":"http_request","json":{
                "/metadata/request_id":{"kind":"random","format":"hex","length":8},
                "/metadata/auth_token":jwt,
                "/metadata/skill_identity_token":jwt
            }},
            "proof":{"source":"src/chat.rs:issue","fact":"Source generates an eight-character hex request ID and signs two request-relative JWTs with the startup key"}}),
    );
    // The installed historical attempt represents the same startup inputs.
    let mut state = fixture.state();
    state.replay_identity = Some(fingerprint::replay_identity(fixture.root()).unwrap());
    fixture.store().save(&state).unwrap();
    (
        dependencies.clone(),
        fs::read(dependencies).unwrap(),
        fs::read(case.join("expected-response.json")).unwrap(),
    )
}

#[test]
fn http_body_jwt_plan_apply_freezes_key_and_requires_fresh_target_replay() {
    for change_key in [false, true] {
        let fixture = Fixture::new();
        let (dependencies, original_recording, original_oracle) = prepare(&fixture, None);
        let original_policy = fs::read(fixture.policy()).unwrap();
        fixture.confirm();
        let planned = fixture.plan().unwrap();
        assert_eq!(planned.traffic_e2e_report["status"], "planned_needs_replay");
        assert_eq!(planned.traffic_e2e_report["preflight"]["rules"][RULE], 1);
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["source_validations"],
            1
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["stateful_target_obligations"],
            json!([RULE])
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["independent_target_validations"],
            0
        );
        assert_eq!(planned.traffic_e2e_report["verified"], false);
        assert!(!serde_json::to_string(&planned).unwrap().contains(KEY));
        assert_eq!(fs::read(fixture.policy()).unwrap(), original_policy);
        let env = fixture
            .root()
            .join(crate::repository::LOCAL_TARGET_ENV_PATH);
        let state = fixture.state();
        let saved = state.rule_plan.as_ref().unwrap().unified.as_ref().unwrap();
        assert!(saved.artifacts.iter().any(|artifact| artifact.path == env));
        if change_key {
            fs::write(&env, "SECRET_KEY=rotated-synthetic-key\n").unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &planned.plan_id).is_err());
            assert_eq!(fs::read(fixture.policy()).unwrap(), original_policy);
        } else {
            let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert_eq!(applied.traffic_e2e_report["verified"], false);
            assert_eq!(
                applied.traffic_e2e_report["status"],
                "applied_pending_replay"
            );
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
            let text = fs::read_to_string(fixture.policy()).unwrap();
            assert!(text.contains("http_request"));
            assert!(!text.contains(KEY));
        }
        assert_eq!(fs::read(&dependencies).unwrap(), original_recording);
        assert_eq!(
            fs::read(
                dependencies
                    .parent()
                    .unwrap()
                    .join("expected-response.json")
            )
            .unwrap(),
            original_oracle
        );
    }
}

#[test]
fn http_body_jwt_plan_rejects_either_source_signature_before_policy_changes() {
    for invalid_token in [false, true] {
        let fixture = Fixture::new();
        let (dependencies, original_recording, original_oracle) =
            prepare(&fixture, Some(invalid_token));
        let original_policy = fs::read(fixture.policy()).unwrap();
        fixture.confirm();
        let error = fixture.plan().unwrap_err();
        assert!(format!("{error:#}").contains("Signature"), "{error:#}");
        assert!(fixture.state().rule_plan.is_none());
        assert_eq!(fs::read(fixture.policy()).unwrap(), original_policy);
        assert_eq!(fs::read(&dependencies).unwrap(), original_recording);
        assert_eq!(
            fs::read(
                dependencies
                    .parent()
                    .unwrap()
                    .join("expected-response.json")
            )
            .unwrap(),
            original_oracle
        );
    }
}
