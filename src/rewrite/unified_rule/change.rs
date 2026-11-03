//! Explicit replacement sets reuse ordinary proof, publication and recovery.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use crate::policy::{NativeEffect, PolicyRule, Surface, TrafficPolicy};

const CHANGE_FORMAT: &str = "traffic-policy-change/v1";

pub(super) struct Proposal {
    pub policy: TrafficPolicy,
    pub explicit_time: bool,
    pub replace_rules: BTreeSet<String>,
    pub replace_sections: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    format: String,
    #[serde(default)]
    replace_rules: Vec<String>,
    #[serde(default)]
    replace_sections: Vec<String>,
    policy: TrafficPolicy,
}

pub(super) fn parse(input: &str) -> Result<Proposal> {
    let value: serde_yaml::Value = serde_yaml::from_str(input)?;
    if value.get("format").and_then(serde_yaml::Value::as_str) != Some(CHANGE_FORMAT) {
        return Ok(Proposal {
            policy: super::parse_proposal(input)?,
            explicit_time: value.get("time").is_some(),
            replace_rules: BTreeSet::new(),
            replace_sections: BTreeSet::new(),
        });
    }
    let explicit_time = value
        .get("policy")
        .and_then(|policy| policy.get("time"))
        .is_some();
    let change: Change = serde_yaml::from_value(value).context("invalid policy change proposal")?;
    ensure!(
        change.format == CHANGE_FORMAT,
        "unsupported policy change format"
    );
    ensure!(
        change.replace_rules.len() <= 256,
        "policy changes permit at most 256 explicit replaced rule IDs"
    );
    let count = change.replace_rules.len();
    let replace_rules = change.replace_rules.into_iter().collect::<BTreeSet<_>>();
    ensure!(
        replace_rules.len() == count,
        "replaced rule IDs must be unique"
    );
    ensure!(
        !replace_rules.iter().any(|id| id.trim().is_empty()),
        "replaced rule IDs must not be blank"
    );
    let count = change.replace_sections.len();
    let replace_sections = change.replace_sections.into_iter().collect::<BTreeSet<_>>();
    ensure!(
        replace_sections.len() == count,
        "replaced sections must be unique"
    );
    for section in &replace_sections {
        let provided = match section.as_str() {
            "json" => change.policy.json.is_some(),
            "time" => explicit_time,
            "mysql" => change.policy.mysql.is_some(),
            "redis" => change.policy.redis.is_some(),
            "http" => change.policy.http.is_some(),
            "async_api" => change.policy.async_api.is_some(),
            _ => anyhow::bail!(
                "unsupported replaced section {section:?}; use time, json, mysql, redis, http or async_api"
            ),
        };
        ensure!(
            provided,
            "replaced section {section:?} must be explicitly provided in policy"
        );
    }
    ensure!(
        !change.policy.rules.is_empty()
            || explicit_time
            || !change.policy.resources.is_empty()
            || change.policy.json.is_some()
            || change.policy.mysql.is_some()
            || change.policy.redis.is_some()
            || change.policy.http.is_some()
            || change.policy.async_api.is_some()
            || !change.policy.signatures.is_empty(),
        "policy changes require explicit replacement declarations or rules with Source proof"
    );
    crate::policy::compile_policy(&change.policy)?;
    Ok(Proposal {
        policy: change.policy,
        explicit_time,
        replace_rules,
        replace_sections,
    })
}

impl Proposal {
    /// Removing an exception restores strict comparison. Every new permission
    /// still passes the complete ordinary Source/Target preflight after merge.
    /// A response/input rule remains bound to the issue's API; resource rules
    /// can consolidate legacy API selectors through complete resource evidence.
    pub(super) fn remove_from(
        &self,
        document: &mut TrafficPolicy,
        active_api: &str,
    ) -> Result<Vec<PolicyRule>> {
        let mut removed = Vec::new();
        for id in &self.replace_rules {
            let rule = document
                .rules
                .iter()
                .find(|rule| rule.id() == id)
                .with_context(|| {
                    format!("replaced rule {id:?} does not exist in the current policy")
                })?;
            let (api, resource) = match rule {
                PolicyRule::Value(rule) => (
                    rule.selector.api.as_deref(),
                    rule.surface != Surface::ApiResponse,
                ),
                PolicyRule::Native(rule) => (
                    rule.selector.api.as_deref(),
                    rule.selector.resource.is_some(),
                ),
            };
            ensure!(
                !matches!(rule, PolicyRule::Native(rule) if matches!(rule.effect,
                    NativeEffect::CaptureBreeze(_) | NativeEffect::CaptureHttpResponse(_))),
                "Source capture and ordered response-rewrite effects cannot be replaced by a value-rule change"
            );
            ensure!(
                resource || api.is_none_or(|api| api == active_api),
                "cannot replace another API's response or inbound rule from this issue"
            );
            removed.push(rule.clone());
        }
        if removed.iter().any(|rule| {
            matches!(rule,
            PolicyRule::Native(rule) if matches!(rule.effect, NativeEffect::CaptureHttp(_)))
        }) {
            let mut candidate = document.clone();
            candidate
                .rules
                .retain(|rule| !self.replace_rules.contains(rule.id()));
            super::proposal::merge(&mut candidate, self.policy.rules.clone())?;
            ensure!(
                capture_paths(document)? == capture_paths(&candidate)?,
                "capture_http consolidation must preserve the exact path union, Source revision and selectors"
            );
        }
        document
            .rules
            .retain(|rule| !self.replace_rules.contains(rule.id()));
        Ok(removed)
    }
}

fn capture_paths(document: &TrafficPolicy) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut paths = BTreeMap::<String, BTreeSet<String>>::new();
    for rule in &document.rules {
        if let PolicyRule::Native(rule) = rule
            && let NativeEffect::CaptureHttp(effect) = &rule.effect
        {
            let scope =
                serde_json::to_string(&(&rule.selector, &rule.when, &effect.source_revision))?;
            paths
                .entry(scope)
                .or_default()
                .extend(effect.case_paths.iter().cloned());
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn time_section_replacement_requires_an_actual_settings_declaration() {
        let provided = json!({"format":CHANGE_FORMAT,"replace_sections":["time"],
            "policy":{"format":"traffic-policy/v3","time":{"default_utc_offset":"+05:30"}}});
        let parsed = parse(&provided.to_string()).unwrap();
        assert!(parsed.explicit_time && parsed.policy.rules.is_empty());
        let mut absent = provided;
        absent["policy"].as_object_mut().unwrap().remove("time");
        assert!(parse(&absent.to_string()).is_err());
    }

    #[test]
    fn async_replacement_keeps_its_logical_section_with_nested_recording_payload() {
        let mut current = super::super::parse_proposal(
            &json!({"format":"traffic-policy/v3","async_api":{"POST /jobs":{
                "end":[{"redis":{"operation":"DEL","key":"done:*"}}]}}})
            .to_string(),
        )
        .unwrap();
        let change = json!({"format":CHANGE_FORMAT,"replace_sections":["async_api"],
            "policy":{"format":"traffic-policy/v3","recording":{"async_api":{}}}});
        let parsed = parse(&change.to_string()).unwrap();
        assert_eq!(
            parsed.replace_sections,
            BTreeSet::from(["async_api".into()])
        );
        assert!(
            super::super::declarations::merge_with_replacements(
                &mut current,
                &parsed.policy,
                &parsed.replace_sections
            )
            .unwrap()
        );
        assert!(current.async_api.as_ref().unwrap().is_empty());
        let rendered = crate::policy::render_policy(&current).unwrap();
        assert_eq!(super::super::parse_proposal(&rendered).unwrap(), current);
        let mut invalid = change.clone();
        invalid["replace_sections"] = json!(["recording.async_api"]);
        assert!(parse(&invalid.to_string()).is_err());
        let mut conflicting = change;
        conflicting["policy"]["async_api"] = json!({});
        assert!(parse(&conflicting.to_string()).is_err());
    }

    fn rule(id: &str, api: &str) -> serde_json::Value {
        json!({"id":id,"match":{"api":api},
            "effect":{"kind":"response_header_date","header":"content-disposition","parameter":"filename","format":"%Y-%m-%d"},
            "proof":{"source":"source.py:filename","fact":"Source includes the current date in the download filename"}})
    }

    fn change(replace: serde_json::Value) -> serde_json::Value {
        json!({"format":CHANGE_FORMAT,"replace_rules":replace,
            "policy":{"format":"traffic-policy/v3","rules":[rule("merged","GET /api")]}})
    }

    #[test]
    fn replacement_is_explicit_and_preserves_unrelated_rules() {
        let mut original = super::super::parse_proposal(
            &json!([rule("old", "GET /api"), rule("other", "GET /other")]).to_string(),
        )
        .unwrap();
        let proposal = parse(&change(json!(["old"])).to_string()).unwrap();
        let removed = proposal.remove_from(&mut original, "GET /api").unwrap();
        assert_eq!(removed[0].id(), "old");
        super::super::proposal::merge(&mut original, proposal.policy.rules).unwrap();
        assert_eq!(
            original
                .rules
                .iter()
                .map(PolicyRule::id)
                .collect::<Vec<_>>(),
            ["other", "merged"]
        );
    }

    #[test]
    fn unknown_ids_and_foreign_primary_scopes_do_not_mutate_policy() {
        for (ids, api) in [
            (json!(["missing"]), "GET /api"),
            (json!(["old"]), "GET /other"),
        ] {
            let mut original =
                super::super::parse_proposal(&rule("old", "GET /api").to_string()).unwrap();
            let before = original.clone();
            let proposal = parse(&change(ids).to_string()).unwrap();
            assert!(proposal.remove_from(&mut original, api).is_err());
            assert_eq!(original, before);
        }
    }

    #[test]
    fn persisted_policy_and_implicit_proposals_do_not_accept_change_fields() {
        let value = change(json!(["old"]));
        assert!(crate::policy::parse_policy(&value.to_string()).is_err());
        let mut invalid = value.clone();
        invalid["extra"] = json!(true);
        assert!(parse(&invalid.to_string()).is_err());
        let mut invalid = value;
        invalid["policy"]["rules"] = json!([]);
        assert!(parse(&invalid.to_string()).is_err());
        assert!(parse(&change(json!([])).to_string()).is_ok());
        assert!(parse(&change(json!(["old", "old"])).to_string()).is_err());
    }

    #[test]
    fn section_replacement_requires_unique_supported_explicitly_provided_sections() {
        let valid = json!({"format":CHANGE_FORMAT,"replace_sections":["json"],
            "policy":{"format":"traffic-policy/v3","json":{"fields":{}}}});
        let parsed = parse(&valid.to_string()).unwrap();
        assert!(parsed.replace_rules.is_empty());
        assert_eq!(parsed.replace_sections, BTreeSet::from(["json".into()]));
        for sections in [
            json!(["json", "json"]),
            json!(["unknown"]),
            json!(["mysql"]),
            json!(["signatures"]),
        ] {
            let mut bad = valid.clone();
            bad["replace_sections"] = sections;
            assert!(parse(&bad.to_string()).is_err(), "accepted {bad}");
        }
        assert!(crate::policy::parse_policy(&valid.to_string()).is_err());
        let missing_headers = json!({"format":CHANGE_FORMAT,"replace_sections":["http"],
            "policy":{"format":"traffic-policy/v3","http":{"requests":[]}}});
        assert!(
            parse(&missing_headers.to_string()).is_ok(),
            "an explicitly empty HTTP map remains a valid whole-format replacement"
        );
    }

    #[test]
    fn capture_consolidation_preserves_paths_and_cannot_remove_source_rewrites() {
        let capture = |id, paths| {
            json!({"id":id,"match":{},
            "effect":{"kind":"capture_http","source_revision":format!("sha256:{}", "a".repeat(64)),"case_paths":paths},
            "proof":{"source":"routes.py:1","fact":"The Source route catalog authorizes these exact paths"}})
        };
        let original = super::super::parse_proposal(
            &json!([
                capture("capture-a", json!(["/a/*"])),
                capture("capture-b", json!(["/b/*"]))
            ])
            .to_string(),
        )
        .unwrap();
        for paths in [json!(["/a/*", "/b/*"]), json!(["/a/*"]), json!(["/**"])] {
            let input = json!({"format":CHANGE_FORMAT,"replace_rules":["capture-a","capture-b"],
                "policy":{"format":"traffic-policy/v3","rules":[capture("capture", paths.clone())]}});
            let proposal = parse(&input.to_string()).unwrap();
            let mut document = original.clone();
            let result = proposal.remove_from(&mut document, "GET /api");
            assert_eq!(result.is_ok(), paths == json!(["/a/*", "/b/*"]));
            if result.is_err() {
                assert_eq!(document, original);
            }
        }
        let proposal = parse(&change(json!(["capture-a"])).to_string()).unwrap();
        assert!(
            proposal
                .remove_from(&mut original.clone(), "GET /api")
                .is_err()
        );
        let rewrite = json!({"id":"rewrite","match":{},"effect":{
            "kind":"capture_http_response","authorities":["source.test"],"methods":["GET"],
            "path":{"kind":"exact","value":"/sandbox"},"status_codes":[],"content_types":[],
            "contract":{"kind":"urls","pointers":["/base_url"]}},
            "proof":{"source":"source.py:1","fact":"Source consumes the selected sandbox URL"}});
        let mut document = super::super::parse_proposal(&rewrite.to_string()).unwrap();
        let original = document.clone();
        let proposal = parse(&change(json!(["rewrite"])).to_string()).unwrap();
        assert!(proposal.remove_from(&mut document, "GET /api").is_err());
        assert_eq!(document, original);
    }
}
