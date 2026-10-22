//! Shared HTTP selector for post-match audit and protected envelope preflight.
use super::pattern::{path_pattern_matches, uri_path};
use crate::policy::{CompiledNativeRule, NativeEffect, Protocol};
use crate::replay::TargetKey;
use std::collections::BTreeMap;

/// The caller must first select API and Source condition. Endpoint, method and
/// path are checked here against the original Source request, never a Target hint.
pub(in crate::replay) fn selected_headers<'a>(
    rules: impl IntoIterator<Item = &'a CompiledNativeRule>,
    target: &TargetKey,
    method: &str,
    uri: &str,
) -> BTreeMap<String, String> {
    rules
        .into_iter()
        .filter_map(|compiled| {
            let rule = &compiled.rule;
            let NativeEffect::HttpClientMetadata(effect) = &rule.effect else {
                return None;
            };
            let selector = &rule.selector;
            let resource = selector.resource.as_ref()?;
            (resource.protocol == Protocol::Http
                && resource.endpoint.host.eq_ignore_ascii_case(&target.host)
                && resource.endpoint.port == target.port
                && selector
                    .operation
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(method))
                && selector
                    .path
                    .as_deref()
                    .is_some_and(|s| path_pattern_matches(s, &uri_path(uri))))
            .then_some((rule, effect))
        })
        .flat_map(|(rule, effect)| {
            effect
                .headers
                .iter()
                .map(move |name| (name.clone(), rule.id.clone()))
        })
        .collect()
}
