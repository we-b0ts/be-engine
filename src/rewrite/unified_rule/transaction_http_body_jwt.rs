//! Global complete-token formats use the sealed transaction without signing inputs.
use super::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

const KEY: &str = "synthetic-outbound-transaction-signing-key";
const NOW: i64 = 1_792_108_801;

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
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v2","json":{"fields":{
            "/metadata/request_id":{"kind":"identity","formats":[{"hex":8}]},
            "/metadata/auth_token":{"kind":"identity","formats":["jwt"]},
            "/metadata/skill_identity_token":{"kind":"identity","formats":["jwt"]}
        }}}),
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
fn global_http_token_formats_plan_apply_without_scope_or_signing_keys() {
    for invalid_signature in [None, Some(false), Some(true)] {
        let fixture = Fixture::new();
        let (dependencies, recording, oracle) = prepare(&fixture, invalid_signature);
        fixture.confirm();
        let plan = fixture.plan().unwrap();
        assert_eq!(plan.traffic_e2e_report["rule_ids"], json!(["global.json"]));
        assert!(
            plan.traffic_e2e_report["expanded_rules"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["independent_target_validations"],
            0
        );
        let env = fixture
            .root()
            .join(crate::repository::LOCAL_TARGET_ENV_PATH);
        assert!(
            !fixture
                .state()
                .rule_plan
                .as_ref()
                .unwrap()
                .unified
                .as_ref()
                .unwrap()
                .artifacts
                .iter()
                .any(|artifact| artifact.path == env)
        );
        let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
        assert_eq!(
            applied.traffic_e2e_report["status"],
            "applied_pending_replay"
        );
        assert!(fixture.state().rule_replay_pending);
        let policy = fs::read_to_string(fixture.policy()).unwrap();
        assert!(policy.contains("jwt"));
        assert!(!policy.contains("http_request"));
        assert!(!policy.contains(KEY));
        assert_eq!(fs::read(&dependencies).unwrap(), recording);
        assert_eq!(
            fs::read(
                dependencies
                    .parent()
                    .unwrap()
                    .join("expected-response.json")
            )
            .unwrap(),
            oracle
        );
    }
}
