//! Select and account for post-match dependency-header timestamp validation.
use super::super::response::ResponseTimestampFormat;
use super::*;

impl ReplayPolicyRuntime {
    pub(in crate::replay) fn http_header_timestamp_rules(
        &self,
        context: &HttpPolicyContext<'_>,
    ) -> BTreeMap<String, (String, ResponseTimestampFormat)> {
        self.loaded
            .document
            .dependency_rules
            .iter()
            .filter(|rule| {
                rule.protocol == DependencyProtocol::Http
                    && rule_matches_http(rule, context.target, context.method, context.recorded_uri)
                    && rule.case_selector.is_none()
            })
            .flat_map(|rule| {
                rule.http
                    .as_ref()
                    .unwrap()
                    .headers
                    .iter()
                    .map(move |(name, field)| {
                        (name.to_ascii_lowercase(), (rule.id.clone(), field.format()))
                    })
            })
            .collect()
    }

    pub(in crate::replay) fn commit_http_header_timestamps(&mut self, validated: &[String]) {
        let mut decision = DependencyRuleDecision::default();
        for rule_id in validated {
            decision
                .usage
                .entry(rule_id.clone())
                .or_default()
                .time_validations += 1;
        }
        self.commit(None, decision);
    }
}
