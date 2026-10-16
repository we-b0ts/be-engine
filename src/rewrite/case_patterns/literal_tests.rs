use super::*;

#[test]
fn catalog_keeps_literal_paths_distinct_when_patterns_are_reapplied() {
    let observed = vec![
        "GET /api/items".into(),
        "GET /api/items/".into(),
        "GET /api/items/7/".into(),
        "GET /api//items/7".into(),
        "GET /api/items/7".into(),
    ];
    let patterns = vec!["/api/items/*".into()];
    let mut catalog = BTreeSet::new();
    extend_catalog(&mut catalog, &observed, &patterns).unwrap();
    recanonicalize_catalog(&mut catalog, &patterns).unwrap();
    assert_eq!(
        catalog,
        BTreeSet::from([
            "GET /api/items".into(),
            "GET /api/items/".into(),
            "GET /api/items/7/".into(),
            "GET /api//items/7".into(),
            "GET /api/items/*".into()
        ])
    );
    let wildcard = BTreeSet::from(["GET /api/items/*".into()]);
    assert!(catalog_covers(
        &wildcard,
        &"GET /api/items/8".parse().unwrap()
    ));
    for literal in ["GET /api/items/8/", "GET /api//items/8"] {
        assert!(!catalog_covers(&wildcard, &literal.parse().unwrap()));
    }
}
