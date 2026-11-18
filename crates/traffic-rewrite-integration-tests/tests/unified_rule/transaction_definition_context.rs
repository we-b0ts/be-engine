//! Partial authoring resolves existing names through the frozen active policy.
use super::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

const KEY: &str = "synthetic-current-profile-key";

#[test]
fn partial_jwt_format_reuses_current_signature_and_freezes_its_private_input() {
    for changed_key in [false, true] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
            fs::write(
                root.join(crate::test_support::LOCAL_TARGET_ENV_PATH),
                format!("SECRET_KEY={KEY}\n"),
            )
            .unwrap();
            write(
                &root.join(".traffic-e2e/policy.yaml"),
                json!({"format":"traffic-policy/v3",
                "signatures":{"default":{"kind":"jwt","algorithm":"HS256","key":{"kind":"target_env","name":"SECRET_KEY"}}}}),
            );
            vec![]
        });
        let token = encode(
            &Header::new(Algorithm::HS256),
            &json!({"sub":"stable"}),
            &EncodingKey::from_secret(KEY.as_bytes()),
        )
        .unwrap();
        let response = json!({"token":token}).to_string();
        fixture.replace_response_bodies(response.as_bytes(), response.as_bytes());
        let partial =
            json!({"format":"traffic-policy/v3","json":{"fields":{"/token":{"kind":"jwt"}}}});
        assert!(
            super::super::parse_proposal(&partial.to_string()).is_err(),
            "partial input cannot compile independently of its current profile"
        );
        write(&fixture.proposal, partial);
        fixture.confirm();
        let original = fs::read(fixture.policy()).unwrap();
        let planned = fixture.plan().unwrap();
        assert_eq!(
            planned.traffic_e2e_report["json"]["fields"]["/token"]["kind"],
            "jwt"
        );
        assert!(
            planned.traffic_e2e_report["preflight"]["independent_target_validations"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(!planned.traffic_e2e_report.to_string().contains(KEY));
        if changed_key {
            fs::write(
                fixture
                    .root()
                    .join(crate::test_support::LOCAL_TARGET_ENV_PATH),
                "SECRET_KEY=rotated\n",
            )
            .unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &planned.plan_id).is_err());
            assert_eq!(fs::read(fixture.policy()).unwrap(), original);
        } else {
            let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
            assert_eq!(
                applied.traffic_e2e_report["status"],
                "applied_pending_replay"
            );
            let policy =
                crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap())
                    .unwrap();
            assert_eq!(policy.signatures.len(), 1);
            assert_eq!(
                policy.json.unwrap().fields["/token"],
                crate::policy::GlobalField::Jwt {
                    signature: "default".into()
                }
            );
        }
    }
}
