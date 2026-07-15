pub(crate) fn matches_segment_pattern(pattern: &str, path: &str) -> bool {
    if !path.starts_with('/') || (path.len() > 1 && (path.ends_with('/') || path.contains("//"))) {
        return false;
    }
    let actual_segments = segments(path);
    let pattern_segments = segments(pattern);
    actual_segments.len() == pattern_segments.len()
        && actual_segments
            .iter()
            .zip(pattern_segments.iter())
            .all(|(actual, expected)| *expected == "*" || actual == expected)
}

pub(crate) fn segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_wildcard_consumes_exactly_one_segment() {
        assert!(matches_segment_pattern("/api/users/*", "/api/users/alice"));
        assert!(!matches_segment_pattern(
            "/api/users/*",
            "/api/users/alice/details"
        ));
        assert!(!matches_segment_pattern("/api/users/*", "/api/users"));
        assert!(!matches_segment_pattern(
            "/api/users/*",
            "/api/users/alice/"
        ));
        assert!(!matches_segment_pattern(
            "/api/users/*",
            "/api//users/alice"
        ));
    }
}
