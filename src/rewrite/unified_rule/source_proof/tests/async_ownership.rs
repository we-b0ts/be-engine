//! Reusable ownership evidence is local, immutable plan input, not runtime policy.
use super::*;

fn proposal() -> serde_json::Value {
    json!({"format":"traffic-policy/v3","source_revision":"source-a",
    "async_api":{"POST /jobs":{
        "when":{"/background":true},
        "end":[{"redis":{"operation":"DEL","key":"done:*"}}],
        "ownership":{
            "proof":{"source":"jobs.py:run","fact":"The created job owns this exact background cleanup"},
            "origin":{
                "resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"service"},
                "tables":["jobs"],"row_match":{"kind":"ASYNC"},"bindings":{"job":"id"}
            },
            "requests":[{
                "protocol":"redis",
                "resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0,"username":"default"},
                "operation":"DEL","arguments":[{"identity":"job","prefix":"done:"}]
            }]
        }
    }}})
}

fn document(value: &serde_json::Value) -> TrafficPolicy {
    crate::policy::parse_policy(&value.to_string()).unwrap()
}

#[test]
fn async_ownership_requires_local_plan_proof_and_omits_it_from_runtime() {
    let value = proposal();
    validate_proposal(&value.to_string()).unwrap();
    let annotated = document(&value);
    let snapshot = SourceProofSnapshot::capture(&annotated).unwrap();
    let rendered = crate::policy::render_policy(&annotated).unwrap();
    assert!(!rendered.contains("proof:"));
    assert!(!rendered.contains("jobs.py"));
    let runtime = crate::policy::parse_policy(&rendered).unwrap();
    let compiled = crate::policy::compile_policy(&runtime).unwrap();
    assert_eq!(
        compiled.fingerprints,
        crate::policy::compile_policy(&annotated)
            .unwrap()
            .fingerprints
    );
    assert!(
        compiled.async_api["POST /jobs"][0]
            .ownership
            .as_ref()
            .unwrap()
            .proof
            .is_none()
    );
    snapshot.verify(&compiled).unwrap();
    assert!(validate_proposal(&rendered).is_err());
    assert!(SourceProofSnapshot::capture(&runtime).is_err());
    let selected = [crate::policy::ASYNC_API_ID.to_owned()].into();
    let summary = snapshot.summary(&selected);
    assert!(summary.contains("POST /jobs scenario 0"));
    assert!(summary.contains("jobs.py:run @ source-a"));
    assert!(summary.contains("exact background cleanup"));
}

#[test]
fn editing_async_source_explanation_changes_the_snapshot_not_runtime_permission() {
    let value = proposal();
    let mut other = value.clone();
    other["async_api"]["POST /jobs"]["ownership"]["proof"]["fact"] =
        json!("A clearer account of the same exact job cleanup");
    let (before, after) = (document(&value), document(&other));
    assert_eq!(
        crate::policy::compile_policy(&before).unwrap().fingerprints,
        crate::policy::compile_policy(&after).unwrap().fingerprints
    );
    assert_ne!(
        SourceProofSnapshot::capture(&before).unwrap().sha256,
        SourceProofSnapshot::capture(&after).unwrap().sha256
    );
}

#[test]
fn async_source_snapshot_rejects_changed_evidence_and_changed_runtime_selectors() {
    let value = proposal();
    let declared = document(&value);
    let snapshot = SourceProofSnapshot::capture(&declared).unwrap();
    let compiled = crate::policy::compile_policy(&declared).unwrap();
    let mut tampered = serde_json::to_value(&snapshot).unwrap();
    tampered["async_api"]["POST /jobs"][0]["ownership"]["proof"]["fact"] = json!("tampered proof");
    let tampered: SourceProofSnapshot = serde_json::from_value(tampered).unwrap();
    assert!(tampered.verify(&compiled).is_err());
    let mut changed = value;
    changed["async_api"]["POST /jobs"]["ownership"]["requests"][0]["arguments"][0]["prefix"] =
        json!("other:");
    let changed = crate::policy::compile_policy(&document(&changed)).unwrap();
    assert!(snapshot.verify(&changed).is_err());
}

#[test]
fn async_local_proof_cannot_borrow_evidence_from_a_parent_or_another_source_revision() {
    let mut value = proposal();
    value["async_api"]["POST /jobs"]["ownership"]
        .as_object_mut()
        .unwrap()
        .remove("proof");
    value["async_api"]["POST /jobs"]["proof"] =
        json!({"source":"other.py:1","fact":"An unrelated parent proof"});
    assert!(validate_proposal(&value.to_string()).is_err());
    let mut value = proposal();
    value["async_api"]["POST /jobs"]["ownership"]["proof"]["source"] =
        json!("jobs.py:run @ other-source");
    assert!(crate::policy::parse_policy(&value.to_string()).is_err());
}

#[test]
fn old_plan_snapshot_without_async_declarations_retains_its_original_identity() {
    let raw = json!({"rules":[],"sha256":crate::policy_evidence::digest(b"[]")});
    let restored: SourceProofSnapshot = serde_json::from_value(raw.clone()).unwrap();
    let policy = crate::policy::parse_and_compile_policy("format: traffic-policy/v3\n").unwrap();
    restored.verify(&policy).unwrap();
    assert_eq!(serde_json::to_value(restored).unwrap(), raw);
}

#[test]
fn async_ownership_merge_and_replacement_keep_old_header_and_current_source_proof_separate() {
    let proposed = document(&proposal());
    let snapshot = SourceProofSnapshot::capture(&proposed).unwrap();
    for replace in [false, true] {
        let mut current = crate::policy::parse_policy(
            "format: traffic-policy/v3\nsource_revision: previous-source\n",
        )
        .unwrap();
        if replace {
            current.async_api = Some(std::collections::BTreeMap::from([(
                "POST /jobs".into(),
                serde_json::from_value(json!({"end":[{"redis":{
                    "operation":"DEL","key":"previous:*"
                }}]}))
                .unwrap(),
            )]));
        }
        let sections = if replace {
            std::collections::BTreeSet::from(["async_api".to_owned()])
        } else {
            Default::default()
        };
        assert!(
            crate::rewrite::unified_rule::declarations::merge_with_replacements(
                &mut current,
                &proposed,
                &sections,
            )
            .unwrap()
        );
        assert_eq!(current.source_revision.as_deref(), Some("previous-source"));
        assert!(
            current.async_api.as_ref().unwrap()["POST /jobs"][0]
                .ownership
                .as_ref()
                .unwrap()
                .proof
                .is_none()
        );
        let compiled = crate::policy::compile_policy(&current).unwrap();
        snapshot.verify(&compiled).unwrap();
        let rendered = crate::policy::render_policy(&current).unwrap();
        assert!(!rendered.contains("proof:"));
        assert_eq!(
            compiled.fingerprints,
            crate::policy::parse_and_compile_policy(&rendered)
                .unwrap()
                .fingerprints
        );
    }
}
