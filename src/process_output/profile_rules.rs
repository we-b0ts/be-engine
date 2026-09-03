use std::collections::BTreeSet;

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

const MAX_PROFILE_BY_TYPE_RULES: usize = 32;
const MAX_PROFILE_TYPE_LENGTH: usize = 128;
const MAX_PROFILE_NAME_LENGTH: usize = 512;
const MAX_DEPENDENCY_COORDINATE_LENGTH: usize = 256;
const MAX_PROFILE_EVIDENCE_LENGTH: usize = 1_024;
const MAX_PROFILE_EVIDENCE_PATHS: usize = 16;
const MAX_PROFILE_EVIDENCE_PATH_LENGTH: usize = 512;
const MOTAN_CLIENT_PROFILE_TYPES: [&str; 4] = [
    "RPC_SERVICE_CLIENT",
    "RPC_SERVICE_CLIENT_V2",
    "RPC_SERVICE_CLIENT_REAL",
    "RPC_SERVICE_CLIENT_REAL_V2",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileByTypeRules {
    #[serde(default)]
    pub(crate) exact_total_count: Vec<String>,
    #[serde(default)]
    pub(crate) source_positive_exists: Vec<String>,
    #[serde(default)]
    pub(crate) allow_target_missing: Vec<ProfileTargetMissingAllowance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileTargetMissingAllowance {
    pub metric: String,
    pub source_revision: String,
    pub dependency_path: Vec<String>,
    pub emitter_evidence: ProfileTargetMissingEmitterEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileTargetMissingEmitterEvidence {
    pub inspected_paths: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileByTypeVerificationRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_target_missing: Vec<ProfileTargetMissingAllowance>,
}

impl Default for ProfileByTypeRules {
    fn default() -> Self {
        Self {
            exact_total_count: vec!["RPC_SERVICE_WHOLE".to_string()],
            source_positive_exists: vec!["HTTP".to_string(), "RPC_SERVICE_CLIENT".to_string()],
            allow_target_missing: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileByTypePolicy {
    ExactTotalCount,
    SourcePositiveExists,
}

impl ProfileByTypeRules {
    pub(super) fn with_verification(verification: Option<&ProfileByTypeVerificationRules>) -> Self {
        let mut rules = Self::default();
        if let Some(verification) = verification {
            rules.allow_target_missing = verification.allow_target_missing.clone();
        }
        rules
    }

    pub(super) fn validate(&self, output_id: &str) -> Result<()> {
        let policy_count = self.exact_total_count.len() + self.source_positive_exists.len();
        ensure!(
            (1..=MAX_PROFILE_BY_TYPE_RULES).contains(&policy_count),
            "process output {output_id} profile_by_type rules must contain 1-{MAX_PROFILE_BY_TYPE_RULES} exact_total_count or source_positive_exists entries"
        );
        let effective_policy_count = self.policies().len();
        let rule_count = effective_policy_count + self.allow_target_missing.len();
        ensure!(
            rule_count <= MAX_PROFILE_BY_TYPE_RULES,
            "process output {output_id} profile_by_type rules must contain at most {MAX_PROFILE_BY_TYPE_RULES} total entries including allow_target_missing"
        );
        for record_type in self
            .exact_total_count
            .iter()
            .chain(&self.source_positive_exists)
        {
            ensure!(
                !record_type.is_empty()
                    && record_type == record_type.trim()
                    && record_type.len() <= MAX_PROFILE_TYPE_LENGTH
                    && !record_type.contains(['\r', '\n']),
                "process output {output_id} profile_by_type rule type must be a trimmed single-line value up to {MAX_PROFILE_TYPE_LENGTH} bytes"
            );
        }
        for record_type in &self.source_positive_exists {
            ensure!(
                !MOTAN_CLIENT_PROFILE_TYPES[1..].contains(&record_type.as_str()),
                "process output {output_id} profile_by_type source_positive_exists must configure RPC_SERVICE_CLIENT once instead of listing its V2 and REAL aliases"
            );
        }
        let policies = self.policies();
        let mut allowed = BTreeSet::new();
        for allowance in &self.allow_target_missing {
            let Some((record_type, name)) = allowance.metric.split_once('.') else {
                bail!(
                    "process output {output_id} profile_by_type allow_target_missing metric must use <type>.<name> format"
                );
            };
            ensure!(
                !record_type.is_empty()
                    && record_type == record_type.trim()
                    && record_type.len() <= MAX_PROFILE_TYPE_LENGTH
                    && !record_type.contains(['\r', '\n'])
                    && !name.is_empty()
                    && name == name.trim()
                    && name.len() <= MAX_PROFILE_NAME_LENGTH
                    && !name.contains(['\r', '\n']),
                "process output {output_id} profile_by_type allow_target_missing metric must use trimmed single-line <type>.<name> values with a type up to {MAX_PROFILE_TYPE_LENGTH} bytes and a name up to {MAX_PROFILE_NAME_LENGTH} bytes"
            );
            let canonical_type = canonical_profile_type(record_type);
            ensure!(
                policies.get(canonical_type) == Some(&ProfileByTypePolicy::SourcePositiveExists),
                "process output {output_id} profile_by_type allow_target_missing metric {:?} must reference a type whose effective policy is source_positive_exists",
                allowance.metric
            );
            ensure!(
                allowed.insert((canonical_type, canonical_profile_name(canonical_type, name))),
                "process output {output_id} profile_by_type allow_target_missing metric {:?} is duplicated",
                allowance.metric
            );
            validate_evidence(output_id, allowance)?;
        }
        Ok(())
    }

    pub(super) fn policies(&self) -> std::collections::BTreeMap<&str, ProfileByTypePolicy> {
        let mut policies = std::collections::BTreeMap::new();
        for record_type in &self.source_positive_exists {
            if record_type == MOTAN_CLIENT_PROFILE_TYPES[0] {
                for expanded in MOTAN_CLIENT_PROFILE_TYPES {
                    policies.insert(expanded, ProfileByTypePolicy::SourcePositiveExists);
                }
            } else {
                policies.insert(
                    record_type.as_str(),
                    ProfileByTypePolicy::SourcePositiveExists,
                );
            }
        }
        for record_type in &self.exact_total_count {
            policies.insert(record_type.as_str(), ProfileByTypePolicy::ExactTotalCount);
        }
        policies
    }

    pub(super) fn allows_target_missing(&self, record_type: &str, name: &str) -> bool {
        self.allow_target_missing.iter().any(|allowance| {
            allowance
                .metric
                .split_once('.')
                .is_some_and(|(allowed_type, allowed_name)| {
                    canonical_profile_type(allowed_type) == canonical_profile_type(record_type)
                        && canonical_profile_name(
                            canonical_profile_type(allowed_type),
                            allowed_name,
                        ) == canonical_profile_name(canonical_profile_type(record_type), name)
                })
        })
    }

    pub(super) fn logical_type<'a>(
        &self,
        record_type: &'a str,
        policy: ProfileByTypePolicy,
    ) -> &'a str {
        if policy == ProfileByTypePolicy::SourcePositiveExists
            && self
                .source_positive_exists
                .iter()
                .any(|configured| configured == MOTAN_CLIENT_PROFILE_TYPES[0])
            && MOTAN_CLIENT_PROFILE_TYPES.contains(&record_type)
        {
            MOTAN_CLIENT_PROFILE_TYPES[0]
        } else {
            record_type
        }
    }
}

pub(crate) fn validate_verification_rules(
    output_id: &str,
    rules: &ProfileByTypeVerificationRules,
) -> Result<()> {
    super::validate_id(output_id)?;
    ProfileByTypeRules::with_verification(Some(rules)).validate(output_id)
}

pub(super) fn canonical_metric(record_type: &str, name: &str) -> String {
    let record_type = canonical_profile_type(record_type);
    format!(
        "{record_type}.{}",
        canonical_profile_name(record_type, name)
    )
}

pub(super) fn canonical_profile_type(record_type: &str) -> &str {
    if MOTAN_CLIENT_PROFILE_TYPES.contains(&record_type) {
        MOTAN_CLIENT_PROFILE_TYPES[0]
    } else {
        record_type
    }
}

pub(super) fn equivalent_profile_types(left: &str, right: &str) -> bool {
    canonical_profile_type(left) == canonical_profile_type(right)
}

fn canonical_profile_name<'a>(record_type: &str, name: &'a str) -> &'a str {
    if record_type == "HTTP"
        && let Some(unprefixed) = name.strip_prefix("all_")
        && (unprefixed.starts_with("http://") || unprefixed.starts_with("https://"))
    {
        return unprefixed;
    }
    name
}

pub(super) fn equivalent_names(record_type: &str, left: &str, right: &str) -> bool {
    canonical_profile_name(record_type, left) == canonical_profile_name(record_type, right)
}

fn validate_evidence(output_id: &str, allowance: &ProfileTargetMissingAllowance) -> Result<()> {
    ensure!(
        (7..=64).contains(&allowance.source_revision.len())
            && allowance
                .source_revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "process output {output_id} profile_by_type allow_target_missing metric {:?} source_revision must be a 7-64 character lowercase hexadecimal revision",
        allowance.metric
    );
    ensure!(
        allowance.dependency_path.len() >= 2,
        "process output {output_id} profile_by_type allow_target_missing metric {:?} dependency_path must identify a direct dependency followed by at least one indirect dependency",
        allowance.metric
    );
    let mut dependencies = BTreeSet::new();
    for dependency in &allowance.dependency_path {
        ensure!(
            valid_single_line(dependency, MAX_DEPENDENCY_COORDINATE_LENGTH),
            "process output {output_id} profile_by_type allow_target_missing metric {:?} dependency_path entries must be trimmed single-line coordinates up to {MAX_DEPENDENCY_COORDINATE_LENGTH} bytes",
            allowance.metric
        );
        ensure!(
            dependencies.insert(dependency.as_str()),
            "process output {output_id} profile_by_type allow_target_missing metric {:?} dependency_path contains duplicate coordinate {dependency:?}",
            allowance.metric
        );
    }
    ensure!(
        (2..=MAX_PROFILE_EVIDENCE_PATHS)
            .contains(&allowance.emitter_evidence.inspected_paths.len()),
        "process output {output_id} profile_by_type allow_target_missing metric {:?} emitter_evidence.inspected_paths must contain 2-{MAX_PROFILE_EVIDENCE_PATHS} source or dependency source paths",
        allowance.metric
    );
    let mut inspected_paths = BTreeSet::new();
    for path in &allowance.emitter_evidence.inspected_paths {
        ensure!(
            valid_single_line(path, MAX_PROFILE_EVIDENCE_PATH_LENGTH),
            "process output {output_id} profile_by_type allow_target_missing metric {:?} emitter_evidence.inspected_paths entries must be trimmed single-line paths up to {MAX_PROFILE_EVIDENCE_PATH_LENGTH} bytes",
            allowance.metric
        );
        ensure!(
            inspected_paths.insert(path.as_str()),
            "process output {output_id} profile_by_type allow_target_missing metric {:?} emitter_evidence.inspected_paths contains duplicate path {path:?}",
            allowance.metric
        );
    }
    ensure!(
        valid_single_line(
            &allowance.emitter_evidence.description,
            MAX_PROFILE_EVIDENCE_LENGTH
        ),
        "process output {output_id} profile_by_type allow_target_missing metric {:?} emitter_evidence.description must be a trimmed single-line value up to {MAX_PROFILE_EVIDENCE_LENGTH} bytes",
        allowance.metric
    );
    Ok(())
}

fn valid_single_line(value: &str, max_length: usize) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.len() <= max_length
        && !value.contains(['\r', '\n'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn motan_client_selector_expands_to_all_four_profile_types() {
        let rules = rules();

        assert_eq!(
            rules.policies().keys().copied().collect::<Vec<_>>(),
            vec![
                "HTTP",
                "RPC_SERVICE_CLIENT",
                "RPC_SERVICE_CLIENT_REAL",
                "RPC_SERVICE_CLIENT_REAL_V2",
                "RPC_SERVICE_CLIENT_V2",
            ]
        );
    }

    #[test]
    fn allow_target_missing_requires_indirect_dependency_evidence() {
        let valid = rules();
        valid.validate("metrics-profile").unwrap();

        let mut missing_name = rules();
        missing_name.allow_target_missing[0].metric = "HTTP.".to_string();
        assert!(
            missing_name
                .validate("metrics-profile")
                .unwrap_err()
                .to_string()
                .contains("<type>.<name>")
        );

        let mut exact_type = rules();
        exact_type.exact_total_count.push("HTTP".to_string());
        assert!(
            exact_type
                .validate("metrics-profile")
                .unwrap_err()
                .to_string()
                .contains("effective policy is source_positive_exists")
        );

        let mut missing_dependency_hop = rules();
        missing_dependency_hop.allow_target_missing[0]
            .dependency_path
            .pop();
        assert!(
            missing_dependency_hop
                .validate("metrics-profile")
                .unwrap_err()
                .to_string()
                .contains("direct dependency followed by at least one indirect dependency")
        );

        let mut missing_inspected_path = rules();
        missing_inspected_path.allow_target_missing[0]
            .emitter_evidence
            .inspected_paths
            .pop();
        assert!(
            missing_inspected_path
                .validate("metrics-profile")
                .unwrap_err()
                .to_string()
                .contains("inspected_paths must contain 2-")
        );

        let mut empty_description = rules();
        empty_description.allow_target_missing[0]
            .emitter_evidence
            .description
            .clear();
        assert!(
            empty_description
                .validate("metrics-profile")
                .unwrap_err()
                .to_string()
                .contains("emitter_evidence.description")
        );
    }

    #[test]
    fn http_header_and_body_metrics_share_one_allowance() {
        let rules = rules();

        assert!(rules.allows_target_missing("HTTP", "http://api.example.com/path"));
        assert!(rules.allows_target_missing("HTTP", "all_http://api.example.com/path"));
    }

    #[test]
    fn motan_aliases_share_one_canonical_allowance() {
        let mut rules = rules();
        rules.allow_target_missing[0].metric =
            "RPC_SERVICE_CLIENT_V2.ExampleService.call()".to_string();

        rules.validate("metrics-profile").unwrap();
        assert_eq!(
            canonical_metric("RPC_SERVICE_CLIENT_V2", "ExampleService.call()"),
            "RPC_SERVICE_CLIENT.ExampleService.call()"
        );
        assert!(rules.allows_target_missing("RPC_SERVICE_CLIENT_REAL_V2", "ExampleService.call()"));
    }

    fn rules() -> ProfileByTypeRules {
        ProfileByTypeRules {
            exact_total_count: Vec::new(),
            source_positive_exists: vec![
                "HTTP".to_string(),
                "RPC_SERVICE_CLIENT".to_string(),
            ],
            allow_target_missing: vec![ProfileTargetMissingAllowance {
                metric: "HTTP.http://api.example.com/path".to_string(),
                source_revision: "0123456789abcdef".to_string(),
                dependency_path: vec![
                    "com.example:direct-client:1.0.0".to_string(),
                    "com.vendor:indirect-emitter:2.0.0".to_string(),
                ],
                emitter_evidence: ProfileTargetMissingEmitterEvidence {
                    inspected_paths: vec![
                        "pom.xml".to_string(),
                        "vendor/src/com/vendor/Emitter.java".to_string(),
                    ],
                    description: "com.vendor.Emitter independently issues the metric operation without affecting source behavior"
                        .to_string(),
                },
            }],
        }
    }
}
