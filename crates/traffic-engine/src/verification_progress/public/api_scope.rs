//! Keep concrete members of confirmed API patterns out of the public API list.
use std::collections::BTreeMap;

pub(super) fn visible_apis<T>(apis: &BTreeMap<String, T>) -> impl Iterator<Item = (&String, &T)> {
    let patterns = apis
        .keys()
        .filter_map(|api| api.split_once(' '))
        .filter(|(_, path)| path.contains('*'))
        .collect::<Vec<_>>();
    apis.iter().filter(move |(api, _)| {
        let Some((method, path)) = api.split_once(' ') else {
            return true;
        };
        path.contains('*')
            || !patterns.iter().any(|(pattern_method, pattern)| {
                method == *pattern_method
                    && crate::path_pattern::matches_path_pattern(pattern, path)
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_confirmed_same_method_patterns_hide_concrete_members() {
        let apis = [
            "GET /attachments/*/download",
            "GET /attachments/123/download",
            "GET /attachments/opaque-id/download",
            "POST /attachments/123/download",
            "GET /api/v1/status",
            "GET /unconfigured/123",
            "GET /api/namespaces/**",
            "GET /api/namespaces/team-a/pods/1",
            "GET /api/namespaces",
        ]
        .map(|api| (api.to_string(), ()))
        .into();
        let visible = visible_apis(&apis)
            .map(|(api, _)| api.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            visible,
            [
                "GET /api/namespaces",
                "GET /api/namespaces/**",
                "GET /api/v1/status",
                "GET /attachments/*/download",
                "GET /unconfigured/123",
                "POST /attachments/123/download",
            ]
        );
    }
}
