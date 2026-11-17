//! Custom input signing uses the public stale-safe proposal transaction.
use super::*;
use md5::{Digest, Md5};

#[test]
fn signed_input_plan_apply_freezes_secret_and_requires_fresh_replay() {
    for change_key in [false, true] {
        let fixture = Fixture::new();
        let env = fixture
            .root()
            .join(crate::repository::LOCAL_TARGET_ENV_PATH);
        fs::write(&env, "LOGIN_SECRET=test-key\n").unwrap();
        let request = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/00000000-0000-4000-8000-000000000001/request.json");
        let sign = format!(
            "{:x}",
            Md5::digest(b"timestamp=1792108800&user=user&secret=test-key")
        );
        write(
            &request,
            json!({"method":"GET","uri":"/api","timestamp":"2026-10-16T00:00:00Z","headers":{},
            "body":body(json!({"timestamp":"1792108800","user":"user","sign":sign}))}),
        );
        let original_request = fs::read(&request).unwrap();
        write(
            &fixture.proposal,
            json!({"id":"signed-login","match":{"api":"GET /api"},"effect":{
            "kind":"input_signed_timestamp","algorithm":"md5_sorted_fields",
            "fields":{"timestamp":"/timestamp","user":"/user"},"timestamp_pointer":"/timestamp",
            "signature_pointer":"/sign","secret_parameter":"secret","time":"preserve_relative",
            "signing_key":{"kind":"target_env","name":"LOGIN_SECRET"}},
            "proof":{"source":"src/login.rs:verify","fact":"Source verifies trimmed sorted string fields and an inbound timestamp window"}}),
        );
        // The installed historical attempt represents execution with this
        // initial startup secret; later rotation must still fail the stale gate.
        let mut state = fixture.state();
        state.replay_identity = Some(fingerprint::replay_identity(fixture.root()).unwrap());
        fixture.store().save(&state).unwrap();
        fixture.confirm();
        let planned = fixture.plan().unwrap();
        assert_eq!(planned.traffic_e2e_report["status"], "planned_needs_replay");
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["rules"]["signed-login"],
            1
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["stateful_target_obligations"],
            json!(["signed-login"])
        );
        assert!(
            !serde_json::to_string(&planned)
                .unwrap()
                .contains("test-key")
        );
        if change_key {
            fs::write(&env, "LOGIN_SECRET=rotated-key\n").unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &planned.plan_id).is_err());
            assert!(
                !fs::read_to_string(fixture.policy())
                    .unwrap()
                    .contains("input_signed_timestamp")
            );
        } else {
            let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert_eq!(applied.traffic_e2e_report["verified"], false);
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
            assert!(
                !fs::read_to_string(fixture.policy())
                    .unwrap()
                    .contains("test-key")
            );
        }
        assert_eq!(fs::read(request).unwrap(), original_request);
    }
}
