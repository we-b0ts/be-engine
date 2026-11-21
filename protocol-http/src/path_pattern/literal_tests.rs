use super::*;

#[test]
fn exact_paths_keep_separators_encoding_case_and_method_independent_identity() {
    for path in ["/api/v1/auth/tokens/", "/api//items", "/", "/api/%2f/"] {
        validate_path_selector(path).unwrap();
        assert!(matches_path_pattern(path, path));
        assert!(path_patterns_overlap(path, path));
        assert!(path_pattern_covers(path, path));
    }
    for (left, right) in [
        ("/a/", "/a"),
        ("/api//a", "/api/a"),
        ("/a/%2f", "/a/%2F"),
        ("/a/", "/A/"),
    ] {
        assert!(!matches_path_pattern(left, right));
        assert!(!path_patterns_overlap(left, right));
        assert!(!path_pattern_covers(left, right));
    }
    for path in ["/api/7/", "/api//7"] {
        for pattern in ["/api/*", "/api/**"] {
            assert!(!matches_path_pattern(pattern, path));
            assert!(!path_patterns_overlap(pattern, path));
            assert!(!path_patterns_overlap(path, pattern));
            assert!(!path_pattern_covers(pattern, path));
        }
    }
}
#[test]
fn invalid_literals_and_noncanonical_wildcards_remain_rejected() {
    for invalid in [
        "api/a",
        "/a?x=1",
        "/a#fragment",
        "/a b",
        "/a\n",
        "/a\t",
        "/api/*/",
        "/api//*/x",
        "/api/**/x",
        "/api/a*b",
    ] {
        assert!(validate_path_selector(invalid).is_err(), "{invalid:?}");
        assert!(!matches_path_pattern(invalid, invalid), "{invalid:?}");
    }
    // Configuration wildcard grammar is unchanged, including its canonical literals.
    assert!(validate_path_pattern("/api/a/").is_err());
    assert!(validate_path_pattern("/api/*/").is_err());
}
