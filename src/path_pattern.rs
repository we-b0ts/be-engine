use anyhow::{Result, ensure};

pub(crate) fn validate_path_pattern(pattern: &str) -> Result<()> {
    ensure!(
        pattern.starts_with('/'),
        "API path pattern must start with '/': {pattern}"
    );
    ensure!(
        !pattern.contains(['?', '#', '\r', '\n']),
        "API path pattern must contain only a URI path: {pattern}"
    );
    let segments = segments(pattern);
    ensure!(
        !segments.is_empty(),
        "API path pattern must not match the root path"
    );
    ensure!(
        format!("/{}", segments.join("/")) == pattern,
        "API path pattern must use canonical separators with no trailing slash: {pattern}"
    );
    ensure!(
        segments
            .iter()
            .all(|segment| !segment.contains('*') || *segment == "*" || *segment == "**"),
        "API path pattern wildcards must occupy a whole path segment: {pattern}"
    );
    ensure!(
        segments
            .iter()
            .enumerate()
            .all(|(index, segment)| *segment != "**" || index == segments.len() - 1),
        "API path pattern '**' catch-all must be the final path segment: {pattern}"
    );
    Ok(())
}

pub(crate) fn matches_path_pattern(pattern: &str, path: &str) -> bool {
    if !canonical_path(pattern) || !canonical_path(path) {
        return false;
    }
    let actual_segments = segments(path);
    let pattern_segments = segments(pattern);
    let catch_all = pattern_segments.last() == Some(&"**");
    if pattern_segments
        .iter()
        .take(
            pattern_segments
                .len()
                .saturating_sub(usize::from(catch_all)),
        )
        .any(|segment| *segment == "**")
    {
        return false;
    }
    let fixed_segments = if catch_all {
        &pattern_segments[..pattern_segments.len() - 1]
    } else {
        &pattern_segments
    };
    let length_matches = if catch_all {
        actual_segments.len() > fixed_segments.len()
    } else {
        actual_segments.len() == fixed_segments.len()
    };
    length_matches
        && actual_segments
            .iter()
            .zip(fixed_segments)
            .all(|(actual, expected)| *expected == "*" || actual == expected)
}

pub(crate) fn path_patterns_overlap(left: &str, right: &str) -> bool {
    let Some((left_segments, left_catch_all)) = parsed_pattern(left) else {
        return false;
    };
    let Some((right_segments, right_catch_all)) = parsed_pattern(right) else {
        return false;
    };
    let left_fixed = fixed_segments(&left_segments, left_catch_all);
    let right_fixed = fixed_segments(&right_segments, right_catch_all);

    let compatible_lengths = match (left_catch_all, right_catch_all) {
        (false, false) => left_fixed.len() == right_fixed.len(),
        (true, false) => right_fixed.len() > left_fixed.len(),
        (false, true) => left_fixed.len() > right_fixed.len(),
        (true, true) => true,
    };
    compatible_lengths
        && left_fixed
            .iter()
            .zip(right_fixed)
            .all(|(left, right)| left == right || *left == "*" || *right == "*")
}

pub(crate) fn segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn canonical_path(path: &str) -> bool {
    path.starts_with('/') && (path.len() == 1 || (!path.ends_with('/') && !path.contains("//")))
}

fn parsed_pattern(pattern: &str) -> Option<(Vec<&str>, bool)> {
    if !canonical_path(pattern) {
        return None;
    }
    let segments = segments(pattern);
    let catch_all = segments.last() == Some(&"**");
    if segments
        .iter()
        .take(segments.len().saturating_sub(usize::from(catch_all)))
        .any(|segment| *segment == "**")
    {
        return None;
    }
    Some((segments, catch_all))
}

fn fixed_segments<'a>(segments: &'a [&str], catch_all: bool) -> &'a [&'a str] {
    if catch_all {
        &segments[..segments.len() - 1]
    } else {
        segments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_wildcard_consumes_exactly_one_segment() {
        assert!(matches_path_pattern("/api/users/*", "/api/users/alice"));
        assert!(!matches_path_pattern(
            "/api/users/*",
            "/api/users/alice/details"
        ));
        assert!(!matches_path_pattern("/api/users/*", "/api/users"));
        assert!(!matches_path_pattern("/api/users/*", "/api/users/alice/"));
        assert!(!matches_path_pattern("/api/users/*", "/api//users/alice"));
    }

    #[test]
    fn trailing_catch_all_consumes_one_or_more_segments() {
        assert!(matches_path_pattern(
            "/api/namespaces/**",
            "/api/namespaces/default"
        ));
        assert!(matches_path_pattern(
            "/api/namespaces/**",
            "/api/namespaces/default/pods/nginx"
        ));
        assert!(!matches_path_pattern(
            "/api/namespaces/**",
            "/api/namespaces"
        ));
        assert!(!matches_path_pattern("/api/**/pods", "/api/default/pods"));
    }

    #[test]
    fn detects_overlap_with_trailing_catch_all() {
        assert!(path_patterns_overlap(
            "/api/namespaces/**",
            "/api/namespaces/*/pods/*"
        ));
        assert!(path_patterns_overlap(
            "/api/namespaces/*",
            "/api/namespaces/**"
        ));
        assert!(!path_patterns_overlap("/api/namespaces/**", "/api/users/*"));
        assert!(!path_patterns_overlap(
            "/api/namespaces/**",
            "/api/namespaces"
        ));
    }
}
