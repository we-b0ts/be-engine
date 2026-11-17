use crate::policy::{CompiledPolicy, parse_and_compile_policy};
use crate::value_contract::{global, json::AnchorClocks};
use serde_json::json;

const ORIGINAL_KEY: &str = "signature-registry-private-original-fixture";
const CHANGED_KEY: &str = "signature-registry-private-changed-fixture";
const ENV_NAME: &str = "SIGNATURE_REGISTRY_TEST_KEY";

fn policy() -> CompiledPolicy {
    parse_and_compile_policy(
        r#"format: traffic-policy/v3
signatures:
  default:
    kind: jwt
    algorithm: HS256
    key: {kind: target_env, name: SIGNATURE_REGISTRY_TEST_KEY}
  unused:
    kind: jwt
    algorithm: HS512
    key: {kind: target_file, path: /absent-signature-registry-fixture.env, field: UNUSED}
json:
  fields:
    /token: {kind: jwt}
"#,
    )
    .unwrap()
}

#[test]
fn startup_key_snapshot_is_immutable_while_plan_freshness_detects_changed_inputs() {
    let root = tempfile::tempdir().unwrap();
    crate::startup::ensure_startup_environment(root.path(), ENV_NAME, ORIGINAL_KEY).unwrap();
    let environment = root.path().join(crate::repository::LOCAL_TARGET_ENV_PATH);
    let policy = policy();
    let plan = policy.global_json.as_ref().unwrap();
    let registry = &plan.signatures;
    assert!(registry.needs_prepare());
    assert!(registry.get("default").is_err());

    registry.prepare(root.path()).unwrap();
    assert!(!registry.needs_prepare());
    assert_eq!(registry.get("default").unwrap().1, ORIGINAL_KEY.as_bytes());
    assert!(registry.get("unused").is_err());
    let keys = registry.resolved_keys();
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    key.ensure_current().unwrap();
    let (witness_path, witness_digest) = key.witnesses().next().unwrap();
    assert_eq!(witness_path, &environment);
    assert_eq!(
        witness_digest,
        &crate::policy_evidence::digest(&std::fs::read(&environment).unwrap())
    );

    crate::startup::ensure_startup_environment(root.path(), ENV_NAME, CHANGED_KEY).unwrap();
    assert!(key.ensure_current().is_err());
    assert_ne!(
        witness_digest,
        &crate::policy_evidence::digest(&std::fs::read(&environment).unwrap())
    );
    registry.prepare(root.path()).unwrap();
    assert_eq!(registry.get("default").unwrap().1, ORIGINAL_KEY.as_bytes());

    // Runtime verification borrows the frozen snapshot. It cannot reread the
    // startup file or switch keys while comparing a candidate payload.
    std::fs::remove_file(&environment).unwrap();
    registry.prepare(root.path()).unwrap();
    let source = json!({"token": crate::request_rules::tests::token(
        json!({"sub":"same-user"}), ORIGINAL_KEY
    )});
    let checked =
        global::compare_logical(&source, &source, plan, &[], AnchorClocks::default()).unwrap();
    assert!(checked.passed(), "{:?}", checked.differences);
    let changed = json!({"token": crate::request_rules::tests::token(
        json!({"sub":"same-user"}), CHANGED_KEY
    )});
    let rejected =
        global::compare_logical(&source, &changed, plan, &[], AnchorClocks::default()).unwrap();
    assert!(!rejected.passed());
    assert!(!environment.exists());

    let debug = format!("{policy:?}");
    let serialized = serde_json::to_string(&policy).unwrap();
    for private in [ORIGINAL_KEY, CHANGED_KEY] {
        assert!(!debug.contains(private));
        assert!(!serialized.contains(private));
    }
    assert!(debug.contains("prepared: true"));
    assert!(!serialized.contains("resolved_keys"));
}

#[test]
fn compilation_validates_profiles_without_resolving_startup_inputs() {
    let root = tempfile::tempdir().unwrap();
    let document = crate::policy::parse_policy(
        r#"format: traffic-policy/v3
signatures:
  default: {kind: jwt, algorithm: HS256, key: {kind: target_file, path: /absent-signature-registry-fixture.env, field: SECRET}}
json:
  fields:
    /token: {kind: jwt}
"#,
    )
    .unwrap();
    let compiled = crate::policy::compile_policy(&document).unwrap();
    let registry = &compiled.global_json.as_ref().unwrap().signatures;
    assert!(registry.needs_prepare());
    assert!(registry.resolved_keys().is_empty());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    assert!(registry.prepare(root.path()).is_err());
    assert!(registry.needs_prepare());
    assert!(registry.resolved_keys().is_empty());
}

#[test]
fn jwt_fields_fail_closed_for_missing_wrong_kind_and_invalid_profiles() {
    for signatures in [
        json!({}),
        json!({"other":{"kind":"jwt","algorithm":"HS256","key":{"kind":"target_env","name":"SECRET"}}}),
        json!({"default":{"kind":"md5_sorted_fields","key":{"kind":"target_env","name":"SECRET"}}}),
        json!({"default":{"kind":"jwt","algorithm":"none","key":{"kind":"target_env","name":"SECRET"}}}),
        json!({"default":{"kind":"jwt","algorithm":"HS256","key":{"kind":"target_env","name":""}}}),
    ] {
        let document = json!({"format":"traffic-policy/v3","signatures":signatures,
            "json":{"fields":{"/token":{"kind":"jwt"}}}});
        assert!(parse_and_compile_policy(&document.to_string()).is_err());
    }
    let unknown_reference = json!({"format":"traffic-policy/v3",
        "signatures":{"default":{"kind":"jwt","algorithm":"HS256","key":{"kind":"target_env","name":"SECRET"}}},
        "json":{"fields":{"/token":{"kind":"jwt","signature":"missing"}}}});
    assert!(parse_and_compile_policy(&unknown_reference.to_string()).is_err());
}
