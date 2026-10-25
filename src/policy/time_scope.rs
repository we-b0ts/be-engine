//! Explicit relationship scopes keep clock names independent of sampled entities.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "ScopeDocument", into = "ScopeDocument")]
pub enum ClockScope {
    #[default]
    Shared,
    ArrayElement,
    Entity {
        relative_pointer: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum ScopeDocument {
    Named(ScopeName),
    Entity { relative_pointer: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScopeName {
    Shared,
    ArrayElement,
}

impl From<ScopeDocument> for ClockScope {
    fn from(value: ScopeDocument) -> Self {
        match value {
            ScopeDocument::Named(ScopeName::Shared) => Self::Shared,
            ScopeDocument::Named(ScopeName::ArrayElement) => Self::ArrayElement,
            ScopeDocument::Entity { relative_pointer } => Self::Entity { relative_pointer },
        }
    }
}

impl From<ClockScope> for ScopeDocument {
    fn from(value: ClockScope) -> Self {
        match value {
            ClockScope::Shared => Self::Named(ScopeName::Shared),
            ClockScope::ArrayElement => Self::Named(ScopeName::ArrayElement),
            ClockScope::Entity { relative_pointer } => Self::Entity { relative_pointer },
        }
    }
}

impl ClockScope {
    pub fn is_shared(&self) -> bool {
        matches!(self, Self::Shared)
    }

    pub(crate) fn validate(&self, pointer: &str) -> Result<()> {
        match self {
            Self::Shared => Ok(()),
            Self::ArrayElement => {
                ensure!(
                    pointer.split('/').any(|part| part == "*"),
                    "array_element clock_scope requires an array wildcard field"
                );
                Ok(())
            }
            Self::Entity { relative_pointer } => {
                ensure!(
                    relative_pointer.starts_with("../") && !relative_pointer.contains('*'),
                    "entity clock_scope requires an exact sibling pointer"
                );
                super::validate_pointer(&relative_pointer[2..], false)?;
                ensure!(
                    relative_pointer[3..]
                        .split('/')
                        .all(|part| !matches!(part, "." | "..")),
                    "clock_scope cannot escape its sibling scope"
                );
                ensure!(
                    !pointer.is_empty() && self.peer_pointer(pointer).as_deref() != Some(pointer),
                    "clock_scope requires a distinct identity sibling"
                );
                Ok(())
            }
        }
    }

    pub(crate) fn peer_pointer(&self, pointer: &str) -> Option<String> {
        let Self::Entity {
            relative_pointer, ..
        } = self
        else {
            return None;
        };
        let (parent, _) = pointer.rsplit_once('/')?;
        Some(format!("{parent}{}", relative_pointer.strip_prefix("..")?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{self, FieldContract, Rule, TrafficPolicy};
    use serde_json::{Value, json};

    fn value_rule(pointer: &str, scope: Value) -> Value {
        json!({"id":"times","surface":"api.response","match":{"api":"GET /stream"},"slot":"body","codec":"json",
            "contract":{pointer:{"kind":"time","format":"unix_milliseconds","relation":"preserve_offset","clock_group":"row-7","clock_scope":scope}},
            "proof":{"source":"blocks.py:create","fact":"Each item owns its generated clock"}})
    }
    fn compile(rules: Vec<Value>) -> Result<policy::CompiledPolicy> {
        // Explicit internal IR fixtures exercise the scalar kernel. Public
        // policies accept only root formats and native effects.
        let rules = rules
            .into_iter()
            .map(|rule| serde_json::from_value::<Rule>(rule).map(Into::into))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        policy::compile_policy(&TrafficPolicy {
            rules,
            ..Default::default()
        })
    }

    #[test]
    fn internal_scope_roundtrip_preserves_names_without_restoring_value_authoring() {
        let rule: Rule =
            serde_json::from_value(value_rule("/blocks/*/timestamp", json!("array_element")))
                .unwrap();
        let serialized = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            serialized["contract"]["/blocks/*/timestamp"]["clock_scope"],
            "array_element"
        );
        assert_eq!(
            serialized["contract"]["/blocks/*/timestamp"]["clock_group"],
            "row-7"
        );
        assert_eq!(serde_json::from_value::<Rule>(serialized).unwrap(), rule);
        let mut default = value_rule("/blocks/*/timestamp", json!("shared"));
        default["contract"]["/blocks/*/timestamp"]
            .as_object_mut()
            .unwrap()
            .remove("clock_scope");
        assert!(
            compile(vec![default]).unwrap().rules[0].rule.contract["/blocks/*/timestamp"]
                .time()
                .unwrap()
                .clock_scope
                .is_shared()
        );
    }

    #[test]
    fn scope_validation_requires_arrays_or_an_identity_sibling() {
        assert!(compile(vec![value_rule("/timestamp", json!("array_element"))]).is_err());
        for scope in [
            json!("unknown"),
            json!({"binding":"removed","relative_pointer":"../id"}),
            json!({"relative_pointer":"../../id"}),
            json!({"relative_pointer":"../*"}),
            json!({"relative_pointer":"../id","unknown":true}),
        ] {
            assert!(compile(vec![value_rule("/blocks/*/timestamp", scope)]).is_err());
        }
        let mut rule = value_rule("/blocks/*/timestamp", json!({"relative_pointer":"../id"}));
        rule["slot"] = serde_json::to_value(crate::policy::Slot::SseData(
            crate::policy::SseSelector::Event("message".into()),
        ))
        .unwrap();
        assert!(compile(vec![rule.clone()]).is_err());
        rule["contract"]["/blocks/*/id"] =
            json!({"kind":"identity","prefix":"text-","format":"decimal"});
        let compiled = compile(vec![rule]).unwrap();
        assert!(matches!(
            compiled.rules[0].rule.contract["/blocks/*/timestamp"]
                .time()
                .unwrap()
                .clock_scope,
            ClockScope::Entity { .. }
        ));
        assert!(matches!(
            compiled.rules[0].rule.contract["/blocks/*/id"],
            FieldContract::Identity { .. }
        ));
    }

    #[test]
    fn scalar_native_adapters_reject_scopes_instead_of_discarding_them() {
        let proof = json!({"source":"source.py:clock","fact":"Synthetic scalar clock for scope admission regression"});
        let mysql = json!({"id":"mysql","match":{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"operation":"COM_QUERY","sql":"UPDATE items SET stamp=? WHERE id=?"},"effect":{"kind":"mysql_values","values":{"0":{"relative_time":"unix_seconds","clock_scope":"array_element"}}},"proof":proof});
        let http = json!({"id":"http","match":{"resource":{"protocol":"http","endpoint":"object.test:443"},"operation":"GET","path":"/object"},"effect":{"kind":"http_request","headers":{"x-amz-date":{"request_time":"amz_date","clock_scope":"array_element"}}},"proof":proof});
        for rule in [mysql, http] {
            assert!(
                policy::parse_and_compile_policy(
                    &json!({"format":"traffic-policy/v2","rules":[rule]}).to_string()
                )
                .is_err()
            );
        }
    }
}
