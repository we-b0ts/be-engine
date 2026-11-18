//! One dependency_rules list on disk; runtime owners receive their typed rule families.
use super::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyDocument {
    version: u8,
    expected_response: ExpectedResponseUsage,
    #[serde(default)]
    dependency_rules: Vec<DependencyEntry>,
    #[serde(
        default,
        skip_serializing_if = "crate::request_rules::RequestRules::is_empty"
    )]
    request_rules: crate::request_rules::RequestRules,
    #[serde(default, skip_serializing_if = "ResponseRules::is_empty")]
    response_rules: ResponseRules,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
enum DependencyEntry {
    Binding(Box<BindingEntry>),
    Protocol(Box<ReplayDependencyRule>),
}

impl<'de> Deserialize<'de> for DependencyEntry {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = serde_yaml::Value::deserialize(deserializer)?;
        // Dispatch on the explicit discriminator, preserving each family's validation errors.
        if value.get("kind").is_some() {
            serde_yaml::from_value(value).map(|entry| Self::Binding(Box::new(entry)))
        } else {
            serde_yaml::from_value(value).map(|rule| Self::Protocol(Box::new(rule)))
        }
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BindingEntry {
    DynamicValue(super::super::dynamic_values::DynamicValueRule),
}

impl TryFrom<PolicyDocument> for ReplayPolicyDocument {
    type Error = anyhow::Error;
    fn try_from(document: PolicyDocument) -> Result<Self> {
        let mut dependency_rules = Vec::new();
        let mut dynamic_values = Vec::new();
        for entry in document.dependency_rules {
            match entry {
                DependencyEntry::Protocol(rule) => dependency_rules.push(*rule),
                DependencyEntry::Binding(entry) => {
                    let BindingEntry::DynamicValue(rule) = *entry;
                    dynamic_values.push(rule);
                }
            }
        }
        Ok(Self {
            version: document.version,
            expected_response: document.expected_response,
            dependency_rules,
            dynamic_values,
            request_rules: document.request_rules,
            response_rules: document.response_rules,
        })
    }
}

impl From<ReplayPolicyDocument> for PolicyDocument {
    fn from(document: ReplayPolicyDocument) -> Self {
        let dependency_rules =
            document
                .dependency_rules
                .into_iter()
                .map(|rule| DependencyEntry::Protocol(Box::new(rule)))
                .chain(document.dynamic_values.into_iter().map(|rule| {
                    DependencyEntry::Binding(Box::new(BindingEntry::DynamicValue(rule)))
                }))
                .collect();
        Self {
            version: document.version,
            expected_response: document.expected_response,
            dependency_rules,
            request_rules: document.request_rules,
            response_rules: document.response_rules,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bindings_are_dependency_entries_and_independent_top_level_values_are_rejected() {
        let yaml = "version: 3\nexpected_response: assertions_only\ndependency_rules:\n  - kind: dynamic_value\n    id: name\n    api: /items\n    targets: [{host: db, port: 3306}]\n    capture: {protocol: mysql, target: {host: db, port: 3306}, database: app, sql: 'SELECT id FROM t WHERE name=?', value_index: 0}\n    source_evidence: 'Generator:create uses a random name'\n";
        let document: ReplayPolicyDocument = serde_yaml::from_str(yaml).unwrap();
        validate_document(&document).unwrap();
        assert_eq!(document.dynamic_values.len(), 1);
        let rendered = serde_yaml::to_string(&document).unwrap();
        assert!(rendered.contains("kind: dynamic_value"));
        assert!(!rendered.contains("dynamic_values:"));
        assert!(
            serde_yaml::from_str::<ReplayPolicyDocument>(&format!("{yaml}dynamic_values: []\n"))
                .is_err()
        );
    }
}
