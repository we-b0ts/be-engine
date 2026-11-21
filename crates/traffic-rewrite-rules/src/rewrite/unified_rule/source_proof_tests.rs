use super::source_proof::*;
use serde_json::json;

fn proposal() -> serde_json::Value {
    json!({"format":"traffic-policy/v3","rules":[{
        "id":"append","match":{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},"operation":"APPEND","key":{"kind":"exact","value":"proof"}},
        "effect":{"kind":"redis_append_stream"},
        "proof":{"source":"session.py:42","fact":"Source appends exact chunks to this stream"}
    }]})
}

#[test]
fn runtime_policy_omits_evidence_but_preserves_runtime_identity_and_business_literals() {
    let annotated = proposal();
    validate_proposal(&annotated.to_string()).unwrap();
    let document = crate::policy::parse_policy(&annotated.to_string()).unwrap();
    let snapshot = SourceProofSnapshot::capture(&document).unwrap();
    let rendered = crate::policy::render_policy(&document).unwrap();
    assert!(!rendered.contains("proof:"));
    assert!(!rendered.contains("session.py"));
    // The physical key named proof is business data, not authoring metadata.
    assert!(rendered.contains("value: proof"));
    let runtime = crate::policy::parse_policy(&rendered).unwrap();
    assert!(runtime.rules[0].proof().is_none());
    let compiled = crate::policy::compile_policy(&runtime).unwrap();
    assert_eq!(
        compiled.fingerprints,
        crate::policy::compile_policy(&document)
            .unwrap()
            .fingerprints
    );
    snapshot.verify(&compiled).unwrap();
    assert!(validate_proposal(&rendered).is_err());
    assert!(SourceProofSnapshot::capture(&runtime).is_err());
    assert_eq!(crate::policy::render_policy(&runtime).unwrap(), rendered);
}

#[test]
fn independent_snapshot_is_hash_bound_and_cannot_authorize_a_different_runtime_permission() {
    let document = crate::policy::parse_policy(&proposal().to_string()).unwrap();
    let snapshot = SourceProofSnapshot::capture(&document).unwrap();
    let compiled = crate::policy::compile_policy(&document).unwrap();
    let raw = serde_json::to_string(&snapshot).unwrap();
    let restored: SourceProofSnapshot = serde_json::from_str(&raw).unwrap();
    restored.verify(&compiled).unwrap();
    let mut tampered: serde_json::Value = serde_json::from_str(&raw).unwrap();
    tampered["rules"][0]["proof"]["fact"] = json!("changed Source evidence");
    let tampered: SourceProofSnapshot = serde_json::from_value(tampered).unwrap();
    assert!(
        tampered
            .verify(&compiled)
            .unwrap_err()
            .to_string()
            .contains("snapshot changed")
    );
    let mut other = proposal();
    other["rules"][0]["match"]["key"]["value"] = json!("other");
    let other =
        crate::policy::compile_policy(&crate::policy::parse_policy(&other.to_string()).unwrap())
            .unwrap();
    assert!(snapshot.verify(&other).is_err());
}

#[test]
fn editing_evidence_alone_does_not_change_runtime_or_capture_fingerprints() {
    let left = proposal();
    let mut right = left.clone();
    right["rules"][0]["proof"]["source"] = json!("session.py:43");
    right["rules"][0]["proof"]["fact"] =
        json!("A clearer explanation of the same exact chunk appends");
    let parse = |value: serde_json::Value| crate::policy::parse_policy(&value.to_string()).unwrap();
    let (left, right) = (parse(left), parse(right));
    assert_eq!(
        crate::policy::compile_policy(&left).unwrap().fingerprints,
        crate::policy::compile_policy(&right).unwrap().fingerprints
    );
    assert_ne!(
        SourceProofSnapshot::capture(&left).unwrap().sha256,
        SourceProofSnapshot::capture(&right).unwrap().sha256
    );
}

#[test]
fn compact_redis_key_behaviors_require_their_own_source_proof_in_a_plan() {
    for (behavior, entry) in [
        ("state.get", json!({"state":{"get":{"transient":["nil"]}}})),
        ("state.set", json!({"state":{"set":"transition"}})),
        ("read_commutation", json!({"read_commutation":true})),
        ("commands", json!({"commands":["SET"]})),
        (
            "key_format",
            json!({"key_format":{"kind":"identity","formats":["uuid_v4"]}, "commands":["SET"]}),
        ),
    ] {
        let mut proposal =
            json!({"format":"traffic-policy/v3", "redis":{"keys":{"current:*":entry}}});
        assert!(
            validate_proposal(&proposal.to_string()).is_err(),
            "{behavior}"
        );
        proposal["redis"]["keys"]["current:*"]["proof"] = json!({
            "source":"session.py:42","fact":"Source owns this key behavior within its recorded lifetime"});
        validate_proposal(&proposal.to_string()).unwrap();
        proposal["redis"]["keys"]["current:*"]["proof"]["source"] = json!("");
        assert!(
            validate_proposal(&proposal.to_string()).is_err(),
            "{behavior}"
        );
    }
    // Content formats do not grant an additional resource behavior.
    validate_proposal(
        &json!({"format":"traffic-policy/v3", "redis":{"keys":{
            "proof": {"kind":"identity","formats":["uuid"]}
        }}})
        .to_string(),
    )
    .unwrap();
}

#[test]
fn dependency_lifetime_plans_require_local_evidence_for_each_request() {
    let proof =
        json!({"source":"cache.py:42","fact":"Source shares only these finite recorded requests"});
    for process in [false, true] {
        let requests = if process {
            json!([
                {"http":{"host":"auth.example.test","method":"GET","path":"/refresh"},"proof":proof},
                {"http":{"host":"keys.example.test","method":"GET","path":"/keys"}}
            ])
        } else {
            json!([
                {"redis":{"operation":"HGET","key":"token_v2","field":"client"},"proof":proof},
                {"http":{"host":"auth.example.test","method":"GET","path":"/keys"}}
            ])
        };
        let mut proposal = if process {
            json!({"format":"traffic-policy/v3", "source_revision":format!("sha256:{}", "1".repeat(64)),
                "process_dependencies":{"tasks":{"refresh_keys":{"requests":requests}}}})
        } else {
            json!({"format":"traffic-policy/v3", "localcache":{"requests":requests}})
        };
        assert!(validate_proposal(&proposal.to_string()).is_err());
        let requests = if process {
            &mut proposal["process_dependencies"]["tasks"]["refresh_keys"]["requests"]
        } else {
            &mut proposal["localcache"]["requests"]
        };
        requests[1]["proof"] = proof.clone();
        validate_proposal(&proposal.to_string()).unwrap();
        let document = crate::policy::parse_policy(&proposal.to_string()).unwrap();
        SourceProofSnapshot::capture(&document).unwrap();
        let rendered = crate::policy::render_policy(&document).unwrap();
        assert!(!rendered.contains("proof:"));
        assert!(validate_proposal(&rendered).is_err());
    }
}

#[test]
fn named_api_signature_positions_require_own_plan_proof_without_runtime_evidence() {
    let mut proposal = json!({"format":"traffic-policy/v3",
        "signatures":{"default":{"kind":"jwt","algorithm":"HS256","key":{"kind":"target_env","name":"SECRET_KEY"}}},
        "api":{"*":{"request":{"headers":{"authorization":{"scheme":"bearer"}}}}}
    });
    assert!(validate_proposal(&proposal.to_string()).is_err());
    proposal["api"]["*"]["request"]["headers"]["authorization"]["proof"] = json!({
        "source":"auth.py:42","fact":"Source authenticates and reuses the request-relative session JWT"});
    validate_proposal(&proposal.to_string()).unwrap();
    let policy = crate::policy::parse_policy(&proposal.to_string()).unwrap();
    SourceProofSnapshot::capture(&policy).unwrap();
    let runtime = crate::policy::render_policy(&policy).unwrap();
    assert!(runtime.contains("signatures:"));
    assert!(runtime.contains("api:"));
    assert!(!runtime.contains("proof:"));
    assert!(validate_proposal(&runtime).is_err());
}
