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
        binding: String,
        relative_pointer: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum ScopeDocument {
    Named(ScopeName),
    Entity {
        binding: String,
        relative_pointer: String,
    },
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
            ScopeDocument::Entity {
                binding,
                relative_pointer,
            } => Self::Entity {
                binding,
                relative_pointer,
            },
        }
    }
}

impl From<ClockScope> for ScopeDocument {
    fn from(value: ClockScope) -> Self {
        match value {
            ClockScope::Shared => Self::Named(ScopeName::Shared),
            ClockScope::ArrayElement => Self::Named(ScopeName::ArrayElement),
            ClockScope::Entity {
                binding,
                relative_pointer,
            } => Self::Entity {
                binding,
                relative_pointer,
            },
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
            Self::Entity {
                binding,
                relative_pointer,
            } => {
                ensure!(
                    !binding.is_empty()
                        && binding.len() <= 64
                        && binding
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
                    "clock_scope binding requires a bounded identity identifier"
                );
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
    use serde_json::json;

    fn value_rule(pointer: &str, scope: serde_json::Value) -> serde_json::Value {
        json!({"id":"times","surface":"api.response","match":{"api":"GET /stream"},
            "slot":{"sse_data":{"event":"message","json_type":"done"}},"codec":"json",
            "contract":{pointer:{"relative_time":"unix_milliseconds","clock_group":"row-7","clock_scope":scope}},
            "proof":{"source":"blocks.py:create","fact":"Each item owns its generated clock"}})
    }

    fn compile(rules: Vec<serde_json::Value>) -> Result<super::super::CompiledPolicy> {
        super::super::parse_and_compile_policy(
            &json!({"format":"traffic-policy/v1","rules":rules}).to_string(),
        )
    }

    #[test]
    fn authoring_roundtrip_preserves_names_and_new_scope_without_changing_defaults() {
        let rule = value_rule("/blocks/*/timestamp", json!("array_element"));
        let document = json!({"format":"traffic-policy/v1","rules":[rule]}).to_string();
        let parsed = super::super::parse_policy(&document).unwrap();
        let rendered = super::super::render_policy(&parsed).unwrap();
        assert!(rendered.contains("clock_group: row-7"));
        assert!(rendered.contains("clock_scope: array_element"));
        assert_eq!(parsed, super::super::parse_policy(&rendered).unwrap());
        let mut old = value_rule("/blocks/*/timestamp", json!("shared"));
        old["contract"]["/blocks/*/timestamp"]
            .as_object_mut()
            .unwrap()
            .remove("clock_scope");
        let compiled = compile(vec![old]).unwrap();
        assert!(
            compiled.rules[0].rule.contract["/blocks/*/timestamp"]
                .time()
                .unwrap()
                .clock_scope
                .is_shared()
        );
    }

    #[test]
    fn scope_validation_requires_arrays_or_an_explicit_identity_sibling() {
        assert!(compile(vec![value_rule("/timestamp", json!("array_element"))]).is_err());
        for scope in [
            json!("unknown"),
            json!({"binding":"block","relative_pointer":"../../id"}),
            json!({"binding":"block","relative_pointer":"../*"}),
            json!({"binding":"block","relative_pointer":"../id","unknown":true}),
        ] {
            assert!(compile(vec![value_rule("/blocks/*/timestamp", scope)]).is_err());
        }
        let mut rule = value_rule(
            "/blocks/*/timestamp",
            json!({"binding":"block","relative_pointer":"../id"}),
        );
        assert!(compile(vec![rule.clone()]).is_err());
        rule["contract"]["/blocks/*/id"] =
            json!({"kind":"identity","binding":"block","prefix":"text-","format":"decimal"});
        assert!(compile(vec![rule.clone()]).is_ok());
        let parsed = super::super::parse_policy(
            &json!({"format":"traffic-policy/v1","rules":[rule]}).to_string(),
        )
        .unwrap();
        assert!(
            super::super::render_policy(&parsed)
                .unwrap()
                .contains("relative_pointer: ../id")
        );
    }

    #[test]
    fn scalar_native_adapters_reject_scopes_instead_of_discarding_them() {
        let proof = json!({"source":"source.py:clock","fact":"Synthetic scalar clock for scope admission regression"});
        let mysql = json!({"id":"mysql","match":{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"operation":"COM_QUERY","sql":"UPDATE items SET stamp=? WHERE id=?"},
            "effect":{"kind":"mysql_values","values":{"0":{"relative_time":"unix_seconds","clock_scope":"array_element"}}},"proof":proof});
        let http = json!({"id":"http","match":{"resource":{"protocol":"http","endpoint":"object.test:443"},"operation":"GET","path":"/object"},
            "effect":{"kind":"http_request","headers":{"x-amz-date":{"request_time":"amz_date","clock_scope":"array_element"}}},"proof":proof});
        for rule in [mysql, http] {
            assert!(compile(vec![rule]).is_err());
        }
    }
}
