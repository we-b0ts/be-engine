use super::*;

fn routes(values: &[&str]) -> HttpSourceRoutes {
    values
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[test]
fn coverage_is_method_specific_and_never_infers_a_new_static_route() {
    let registry = routes(&["GET /items/*"]);
    assert_eq!(
        registry
            .resolve("GET", "/items/upload")
            .unwrap()
            .to_string(),
        "GET /items/*"
    );
    assert!(registry.resolve("POST", "/items/upload").is_none());
    assert_eq!(registry.entries().count(), 1);
    let both = registry.merged(["POST /items/*".into()]).unwrap();
    assert_eq!(
        both.resolve("POST", "/items/upload").unwrap().to_string(),
        "POST /items/*"
    );
}

#[test]
fn confirmed_static_survives_either_registration_order() {
    for entries in [
        ["GET /items/upload", "GET /items/*"],
        ["GET /items/*", "GET /items/upload"],
    ] {
        let registry = routes(&entries);
        assert_eq!(
            registry
                .resolve("GET", "/items/upload")
                .unwrap()
                .to_string(),
            "GET /items/upload"
        );
        assert_eq!(
            registry.resolve("GET", "/items/42").unwrap().to_string(),
            "GET /items/*"
        );
        assert!(!registry.selects("GET", "/items/upload", "/items/*"));
        assert!(registry.permits_static_overlap("GET", "/items/*", "/items/upload"));
        assert!(!registry.permits_static_overlap("POST", "/items/*", "/items/upload"));
    }
}

#[test]
fn static_protection_is_scoped_to_its_registered_method() {
    let registry = routes(&["POST /items/upload", "GET /items/*"]);
    assert_eq!(
        registry
            .resolve("GET", "/items/upload")
            .unwrap()
            .to_string(),
        "GET /items/*"
    );
    assert_eq!(
        registry
            .resolve("POST", "/items/upload")
            .unwrap()
            .to_string(),
        "POST /items/upload"
    );
}

#[test]
fn canonical_round_trip_and_ambiguous_patterns_are_explicit() {
    let registry = routes(&["POST /items/*", "GET /items/upload", "GET /items/*"]);
    let encoded = serde_yaml::to_string(&registry).unwrap();
    assert_eq!(
        serde_yaml::from_str::<HttpSourceRoutes>(&encoded).unwrap(),
        registry
    );
    for entries in [
        vec!["GET /items/*", "GET /items/**"],
        vec!["GET /items/*", "GET /items/*"],
        vec!["get /items/*"],
        vec!["MOTAN /items/*"],
    ] {
        assert!(
            HttpSourceRoutes::try_from(entries.into_iter().map(str::to_owned).collect::<Vec<_>>())
                .is_err()
        );
    }
    assert!(registry.resolve("GET", "/items/upload/").is_none());
}
