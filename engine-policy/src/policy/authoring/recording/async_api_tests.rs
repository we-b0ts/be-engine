use crate::policy::{self, NativeEffect};
use serde_json::{Value, json};

fn ends() -> Value {
    json!({"POST /jobs":[{
        "when_response":{"/status":"in_progress"},
        "end":[{"redis":{"operation":"DEL","key":"job:done:*","occurrence":2}}]
    }]})
}

#[test]
fn async_only_recording_and_legacy_root_share_compilation_and_canonical_output() {
    for async_api in [ends(), json!({})] {
        let nested = json!({"format":"traffic-policy/v3","recording":{"async_api":async_api}});
        let legacy = json!({"format":"traffic-policy/v3","async_api":async_api});
        let document = policy::parse_policy(&nested.to_string()).unwrap();
        let old = policy::parse_policy(&legacy.to_string()).unwrap();
        assert_eq!(document, old);
        assert!(document.source_revision.is_none());
        assert!(document.rules.is_empty());
        let compiled = policy::compile_policy(&document).unwrap();
        assert_eq!(compiled, policy::compile_policy(&old).unwrap());
        assert!(
            compiled.native.is_empty(),
            "async declarations grant no HTTP acquisition"
        );
        let rendered = policy::render_policy(&document).unwrap();
        assert_eq!(rendered, policy::render_policy(&old).unwrap());
        let canonical: serde_yaml::Value = serde_yaml::from_str(&rendered).unwrap();
        assert!(canonical.get("async_api").is_none());
        assert!(canonical["recording"].get("async_api").is_some());
        assert!(canonical["recording"].get("case_paths").is_none());
        assert_eq!(policy::parse_policy(&rendered).unwrap(), document);
        let serialized = serde_yaml::to_string(&document).unwrap();
        assert_eq!(policy::parse_policy(&serialized).unwrap(), document);
        let source = crate::config::SourceTrafficPolicyConfig::parse(
            &rendered,
            std::path::Path::new("policy.yaml"),
        )
        .unwrap();
        assert_eq!(source.async_api, compiled.async_api);
    }
}

#[test]
fn async_render_merges_before_http_scope_without_changing_its_name_proof_or_identity() {
    let revision = format!("sha256:{}", "a".repeat(64));
    let nested = json!({
        "format":"traffic-policy/v3","source_revision":revision,
        "recording":{"async_api":ends(),"case_paths":["/jobs","/api/*"],
            "name":"explicit-source-capture",
            "proof":{"source":"routes.py:12","fact":"Source defines these entrypoints"}}
    });
    let mut legacy = nested.clone();
    let old_async = legacy["recording"]
        .as_object_mut()
        .unwrap()
        .remove("async_api")
        .unwrap();
    legacy["async_api"] = old_async;
    let document = policy::parse_policy(&nested.to_string()).unwrap();
    let old = policy::parse_policy(&legacy.to_string()).unwrap();
    assert_eq!(document, old);
    assert_eq!(document.rules.len(), 1);
    assert_eq!(document.rules[0].id(), "explicit-source-capture");
    assert_eq!(
        document.rules[0].proof().unwrap().source,
        format!("routes.py:12 @ {revision}")
    );
    let native = document.rules[0].as_native().unwrap();
    let NativeEffect::CaptureHttp(effect) = &native.effect else {
        panic!("capture owner")
    };
    assert_eq!(effect.case_paths, ["/jobs", "/api/*"]);
    assert_eq!(effect.source_revision, revision);
    let rendered = policy::render_policy(&document).unwrap();
    let raw: serde_yaml::Value = serde_yaml::from_str(&rendered).unwrap();
    assert!(raw.get("async_api").is_none());
    assert!(raw.get("rules").is_none());
    assert_eq!(raw["recording"]["name"], "explicit-source-capture");
    assert_eq!(
        raw["recording"]["case_paths"].as_sequence().unwrap().len(),
        2
    );
    assert!(rendered.find("  async_api:").unwrap() < rendered.find("  case_paths:").unwrap());
    assert_eq!(
        policy::compile_policy(&document).unwrap().fingerprints,
        policy::parse_and_compile_policy(&rendered)
            .unwrap()
            .fingerprints
    );
    assert_eq!(
        rendered,
        policy::render_policy(&policy::parse_policy(&rendered).unwrap()).unwrap()
    );
}

#[test]
fn old_and_new_locations_conflict_even_when_one_or_both_maps_are_empty() {
    for top in [ends(), json!({})] {
        for nested in [ends(), json!({})] {
            let raw = json!({"format":"traffic-policy/v3","async_api":top,
                "recording":{"async_api":nested}});
            let error = policy::parse_policy(&raw.to_string()).unwrap_err();
            assert!(
                format!("{error:#}").contains("cannot be declared both"),
                "{error:#}"
            );
        }
    }
    for raw in [
        "format: traffic-policy/v3\nrecording: {async_api: null}\n",
        "format: traffic-policy/v3\nrecording: {async_api: {}, case_paths: null}\n",
        "format: traffic-policy/v3\nrecording: {async_api: {}, unknown: true}\n",
        "format: traffic-policy/v3\nrecording: {async_api: {}, name: custom}\n",
        "format: traffic-policy/v3\nrecording: {async_api: {}, proof: {source: 'source.py:1', fact: orphan}}\n",
        "format: traffic-policy/v3\nrecording: {}\n",
        "format: traffic-policy/v3\nrecording:\n  async_api: {}\n  async_api: {}\n",
        "format: traffic-policy/v3\nrecording:\n  async_api:\n    'POST /jobs': {end: [{redis: {operation: DEL, key: done}}]}\n    'POST /jobs': {end: [{redis: {operation: DEL, key: done}}]}\n",
    ] {
        assert!(policy::parse_policy(raw).is_err(), "accepted {raw}");
    }
}
