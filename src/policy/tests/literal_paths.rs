use super::*;
use crate::policy::native as n;

fn response(api: &str) -> TrafficPolicy {
    native_policy(api)
}

#[test]
fn literal_api_rules_preserve_request_identity_and_distinct_fingerprints() {
    let paths = ["/api/items", "/api/items/", "/api//items"];
    let mut identities = std::collections::BTreeSet::new();
    for path in paths {
        let api = format!("GET {path}");
        let compiled = compile_policy(&response(&api)).unwrap();
        assert_eq!(
            compiled.native[0].rule.selector.api.as_deref(),
            Some(api.as_str())
        );
        assert!(identities.insert(compiled.fingerprints.runtime));
        let selector = api.parse::<crate::RecordingApi>().unwrap();
        for candidate in paths {
            assert_eq!(
                selector.matches(&hyper::Method::GET, &candidate.parse().unwrap()),
                candidate == path
            );
        }
        assert!(!selector.matches(&hyper::Method::POST, &path.parse().unwrap()));
    }
}

#[test]
fn dependency_and_native_selectors_share_literal_http_paths_without_widening_patterns() {
    let resource = Some(Resource {
        protocol: Protocol::Http,
        endpoint: Endpoint {
            host: "upstream.test".into(),
            port: 80,
        },
        database: None,
        username: None,
    });
    let proof = Proof {
        source: "source.py:1".into(),
        fact: "Source preserves literal upstream paths".into(),
    };
    let mut native = NativeRule {
        id: "literal-header".into(),
        selector: NativeMatch {
            api: Some("GET /api/items/".into()),
            resource,
            operation: Some("POST".into()),
            path: Some("/upstream//items/".into()),
            ..Default::default()
        },
        effect: NativeEffect::HttpRequest(n::HttpRequestEffect {
            query: Default::default(),
            multipart_boundary: true,
        }),
        proof: Some(proof.clone()),
        when: None,
    };
    assert!(compile_native(&native).is_ok());
    for invalid in [
        "/upstream/*/",
        "/upstream//*/items",
        "/upstream/items?x=1",
        "/upstream/items#x",
        "/upstream/bad path",
    ] {
        native.selector.path = Some(invalid.into());
        assert!(compile_native(&native).is_err(), "{invalid}");
    }
}

#[test]
fn motan_and_explicit_capture_patterns_keep_their_strict_grammar() {
    for invalid in [
        "MOTAN /service/",
        "MOTAN /service//method",
        "GET /api/*/",
        "GET /api//*/items",
        "GET /api?x=1",
        "GET /api#x",
        "get /api",
        "GET /bad path",
    ] {
        assert!(
            parse_policy(&serde_json::to_string(&serde_json::json!({"format":POLICY_FORMAT,"rules":[{
                "id":"invalid","match":{"api":invalid},"effect":{"kind":"response_header_date","header":"date","format":"%Y-%m-%d"},"proof":{"source":"source.py:1","fact":"Literal path proof"}}]})).unwrap()).is_err(),
            "{invalid}"
        );
    }
    assert!(compile_policy(&response("MOTAN /service/method")).is_ok());
    let mut capture = NativeRule {
        id: "capture-literal-url".into(),
        selector: Default::default(),
        when: None,
        proof: Some(Proof {
            source: "src/source.rs:42".into(),
            fact: "The exact upstream endpoint returns a dependent service URL".into(),
        }),
        effect: NativeEffect::CaptureHttpResponse(n::CaptureResponseEffect {
            authorities: vec!["upstream.test".into()],
            methods: vec!["GET".into()],
            path: n::CapturePath::Exact {
                value: "/upstream//items/".into(),
            },
            status_codes: vec![200],
            content_types: vec!["application/json".into()],
            contract: n::CaptureResponseContract::Urls {
                pointers: vec![n::Proven {
                    contract: "/base_url".into(),
                    proof: Some(Proof {
                        source: "src/source.rs:43".into(),
                        fact: "Source consumes this returned URL".into(),
                    }),
                }],
            },
        }),
    };
    assert!(compile_native(&capture).is_ok());
    let NativeEffect::CaptureHttpResponse(effect) = &mut capture.effect else {
        unreachable!()
    };
    effect.path = n::CapturePath::Pattern {
        value: "/upstream//items/".into(),
    };
    assert!(compile_native(&capture).is_err());
}
