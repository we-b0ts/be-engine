use super::*;

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
