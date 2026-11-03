//! Bounded identities of the lifecycle declaration actually selected at capture.
use super::{AsyncApiRule, AsyncApiRules, AsyncEnd};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Explanations are reviewed plan evidence, not runtime declaration identity.
pub(crate) fn async_runtime_declarations(
    rules: &BTreeMap<String, AsyncApiRules>,
) -> BTreeMap<String, AsyncApiRules> {
    let mut rules = rules.clone();
    for scenarios in rules.values_mut() {
        for rule in &mut scenarios.0 {
            if let Some(ownership) = &mut rule.ownership {
                ownership.proof = None;
            }
        }
    }
    rules
}

/// The group identity is shared with the effective attribution rule binding.
/// Adding recording metadata must not change existing policy identities.
pub(crate) fn async_rules_fingerprint(rules: &AsyncApiRules) -> String {
    if rules.iter().any(|rule| {
        rule.ownership
            .as_ref()
            .is_some_and(|ownership| ownership.proof.is_some())
    }) {
        let mut runtime = rules.clone();
        for rule in &mut runtime.0 {
            if let Some(ownership) = &mut rule.ownership {
                ownership.proof = None;
            }
        }
        fingerprint(&runtime)
    } else {
        fingerprint(rules)
    }
}

fn fingerprint(value: &impl Serialize) -> String {
    crate::policy_evidence::digest(
        &serde_json::to_vec(value).expect("typed async lifecycle declarations serialize"),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AsyncRuleProvenance {
    pub version: u8,
    pub rule_id: String,
    pub rule_fingerprint: String,
    pub scenario_index: usize,
    pub scenario_fingerprint: String,
    pub terminals: Vec<AsyncTerminalProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AsyncTerminalProvenance {
    pub protocol: AsyncTerminalProtocol,
    pub selector_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AsyncTerminalProtocol {
    Mysql,
    Redis,
    Http,
}

impl AsyncRuleProvenance {
    pub(crate) fn selected(
        api: &str,
        rules: &AsyncApiRules,
        scenario_index: usize,
    ) -> Option<Self> {
        let rule = rules.get(scenario_index)?;
        Some(Self::for_rule(
            api,
            async_rules_fingerprint(rules),
            scenario_index,
            rule,
        ))
    }

    pub(crate) fn for_rule(
        api: &str,
        rule_fingerprint: String,
        scenario_index: usize,
        rule: &AsyncApiRule,
    ) -> Self {
        let runtime_rule = rule
            .ownership
            .as_ref()
            .is_some_and(|ownership| ownership.proof.is_some())
            .then(|| {
                let mut runtime = rule.clone();
                runtime
                    .ownership
                    .as_mut()
                    .expect("selected ownership")
                    .proof = None;
                runtime
            });
        Self {
            version: 1,
            rule_id: format!("{}:{api}", super::ASYNC_API_ID),
            rule_fingerprint,
            scenario_index,
            scenario_fingerprint: fingerprint(runtime_rule.as_ref().unwrap_or(rule)),
            terminals: rule
                .end
                .iter()
                .map(|end| {
                    let (protocol, occurrence) = match end {
                        AsyncEnd::Mysql(_) => (AsyncTerminalProtocol::Mysql, None),
                        AsyncEnd::Redis(end) => {
                            (AsyncTerminalProtocol::Redis, Some(end.occurrence))
                        }
                        AsyncEnd::Http(_) => (AsyncTerminalProtocol::Http, None),
                    };
                    AsyncTerminalProvenance {
                        protocol,
                        selector_fingerprint: fingerprint(end),
                        occurrence,
                    }
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_ownership_keeps_the_original_serialized_rule_group_identity() {
        let original = br#"[{"when":{},"end":[{"redis":{"operation":"DEL","key":"done:*"}}]}]"#;
        let rules: AsyncApiRules = serde_json::from_slice(original).unwrap();
        assert!(rules[0].ownership.is_none());
        assert_eq!(serde_json::to_vec(&rules).unwrap(), original);
        assert_eq!(
            async_rules_fingerprint(&rules),
            crate::policy_evidence::digest(original)
        );
    }

    #[test]
    fn typed_uncompiled_rules_do_not_include_source_explanations_in_recording_identity() {
        let rules: AsyncApiRules = serde_json::from_value(json!([{
            "when":{},"end":[{"redis":{"operation":"DEL","key":"done:*"}}],
            "ownership":{
                "proof":{"source":"jobs.py:finish","fact":"This job owns the declared cleanup"},
                "origin":{
                    "resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},
                    "tables":["jobs"],"row_match":{"role":"ASYNC"},"bindings":{"job":"id"}
                },
                "requests":[{"protocol":"redis",
                    "resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0,"username":"default"},
                    "operation":"DEL","arguments":[{"identity":"job","prefix":"done:"}]
                }]
            }
        }])).unwrap();
        let mut runtime = rules.clone();
        runtime.0[0].ownership.as_mut().unwrap().proof = None;
        assert_eq!(
            async_rules_fingerprint(&rules),
            async_rules_fingerprint(&runtime)
        );
        assert_eq!(
            AsyncRuleProvenance::selected("POST /jobs", &rules, 0),
            AsyncRuleProvenance::selected("POST /jobs", &runtime, 0)
        );
    }

    #[test]
    fn group_identity_matches_existing_rule_bindings_without_exposing_selectors() {
        let rules: AsyncApiRules = serde_json::from_value(json!([
            {"when_response":{"/status":"queued"},"end":[{"http":{
                "method":"POST","endpoint":"private.test:80","path":"/private-submit"
            }}]},
            {"when_response":{"/status":"in_progress"},"end":[{"redis":{
                "operation":"DEL","key":"private-cancel:*","occurrence":2
            }}]}
        ]))
        .unwrap();
        assert_eq!(
            async_rules_fingerprint(&rules),
            crate::policy_evidence::digest(&serde_json::to_vec(&rules).unwrap())
        );
        let actual = AsyncRuleProvenance::selected("POST /jobs", &rules, 1).unwrap();
        assert_eq!(actual.scenario_index, 1);
        assert_eq!(actual.terminals[0].occurrence, Some(2));
        assert_eq!(actual.terminals[0].protocol, AsyncTerminalProtocol::Redis);
        let public = serde_json::to_string(&actual).unwrap();
        assert!(!public.contains("private-cancel"));
        assert!(!public.contains("private.test"));
        assert!(!public.contains("private-submit"));
        assert!(AsyncRuleProvenance::selected("POST /jobs", &rules, 2).is_none());
    }
}
