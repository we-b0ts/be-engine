use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead as _, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Map, Value};

use super::profile_rules::{equivalent_names, equivalent_profile_types};
use super::{
    ProcessOutputCaptureSide, ProcessOutputComparisonDetail, ProfileByTypePolicy,
    ProfileByTypeRules, ProfileDifferenceDetail, ProfileTypeComparisonDetail,
};

#[derive(Debug, Clone)]
pub(super) struct ComparisonOutcome {
    pub(super) passed: bool,
    pub(super) classification: &'static str,
    pub(super) detail: Option<ProcessOutputComparisonDetail>,
}

#[derive(Debug, Default)]
struct ProfileAggregate {
    total_count: u64,
    slow_thresholds: BTreeSet<u64>,
}

type ProfileRecords = BTreeMap<String, BTreeMap<String, ProfileAggregate>>;

pub(super) fn compare(
    source_path: &Path,
    target_path: &Path,
    rules: &ProfileByTypeRules,
) -> Result<ComparisonOutcome> {
    let source = parse(source_path, ProcessOutputCaptureSide::Source, rules)?;
    let target = parse(target_path, ProcessOutputCaptureSide::Target, rules)?;
    let policies = rules.policies();
    let mut compared_types = BTreeSet::new();
    let mut logical_differences = BTreeMap::new();

    for (record_type, policy) in policies {
        let logical_type = rules.logical_type(record_type, policy);
        compared_types.insert(logical_type.to_string());
        let source_records = source.get(record_type);
        let target_records = target.get(record_type);
        let comparison = match policy {
            ProfileByTypePolicy::ExactTotalCount => compare_exact(source_records, target_records),
            ProfileByTypePolicy::SourcePositiveExists => compare_source_positive_exists(
                record_type,
                source_records,
                target_records,
                &target,
                rules,
            ),
        };
        if comparison.difference_count > 0 {
            let mut example = comparison
                .example
                .expect("a nonzero profile difference count must have an example");
            if logical_type != record_type {
                example.observed_type = Some(record_type.to_string());
            }
            let entry = logical_differences
                .entry(logical_type.to_string())
                .or_insert_with(|| ProfileTypeComparisonDetail {
                    record_type: logical_type.to_string(),
                    policy,
                    difference_count: 0,
                    example,
                });
            entry.difference_count = entry
                .difference_count
                .checked_add(comparison.difference_count)
                .context("profile comparison difference count overflowed")?;
        }
    }

    let compared_type_count = compared_types.len();
    let types = logical_differences.into_values().collect::<Vec<_>>();
    if !types.is_empty() {
        let total_difference_count = types.iter().try_fold(0usize, |total, detail| {
            total
                .checked_add(detail.difference_count)
                .context("profile comparison difference count overflowed")
        })?;
        return Ok(ComparisonOutcome {
            passed: false,
            classification: "profile_mismatch",
            detail: Some(ProcessOutputComparisonDetail {
                compared_type_count,
                mismatched_type_count: types.len(),
                total_difference_count,
                types,
            }),
        });
    }

    Ok(ComparisonOutcome {
        passed: true,
        classification: "equal",
        detail: None,
    })
}

fn parse(
    path: &Path,
    side: ProcessOutputCaptureSide,
    rules: &ProfileByTypeRules,
) -> Result<ProfileRecords> {
    let policies = rules.policies();
    let file = File::open(path).with_context(|| {
        format!(
            "failed to open {} profile output {}",
            side_name(side),
            path.display()
        )
    })?;
    let mut records = ProfileRecords::new();

    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.with_context(|| {
            format!(
                "failed to read {} profile output {} line {}",
                side_name(side),
                path.display(),
                index + 1
            )
        })?;
        let Some(json) = line.split_once('{').map(|(_, json)| format!("{{{json}")) else {
            continue;
        };
        let value: Value = serde_json::from_str(&json).with_context(|| {
            format!(
                "invalid JSON in {} profile output {} line {}",
                side_name(side),
                path.display(),
                index + 1
            )
        })?;
        let object = value.as_object().with_context(|| {
            format!(
                "{} profile output {} line {} must contain a JSON object",
                side_name(side),
                path.display(),
                index + 1
            )
        })?;
        let Some(record_type) = object.get("type").and_then(Value::as_str) else {
            continue;
        };
        let Some(policy) = policies.get(record_type) else {
            continue;
        };
        match policy {
            ProfileByTypePolicy::ExactTotalCount => {
                let Some(slow_threshold) =
                    optional_u64(object, "slowThreshold", side, path, index + 1)?
                else {
                    // Profile logs reuse types such as MC for non-latency
                    // snapshots (for example socket-pool sizes). Only
                    // threshold-bearing source records define exact groups.
                    continue;
                };
                let name = required_string(object, "name", side, path, index + 1)?;
                let aggregate = records
                    .entry(record_type.to_string())
                    .or_default()
                    .entry(name)
                    .or_default();
                add_total_count(aggregate, object, side, path, index + 1)?;
                aggregate.slow_thresholds.insert(slow_threshold);
            }
            ProfileByTypePolicy::SourcePositiveExists
                if side == ProcessOutputCaptureSide::Source =>
            {
                if optional_u64(object, "slowThreshold", side, path, index + 1)?.is_none() {
                    // Some legacy types also carry non-latency state rows, for
                    // example MC socket-pool snapshots. They do not define a
                    // comparable metric group.
                    continue;
                }
                let name = required_string(object, "name", side, path, index + 1)?;
                let aggregate = records
                    .entry(record_type.to_string())
                    .or_default()
                    .entry(name)
                    .or_default();
                add_total_count(aggregate, object, side, path, index + 1)?;
            }
            ProfileByTypePolicy::SourcePositiveExists => {
                let name = required_string(object, "name", side, path, index + 1)?;
                records
                    .entry(record_type.to_string())
                    .or_default()
                    .entry(name)
                    .or_default();
            }
        }
    }
    Ok(records)
}

#[derive(Debug, Default)]
struct TypeComparison {
    difference_count: usize,
    example: Option<ProfileDifferenceDetail>,
}

impl TypeComparison {
    fn record(&mut self, example: ProfileDifferenceDetail) {
        self.difference_count += 1;
        if self.example.is_none() {
            self.example = Some(example);
        }
    }
}

fn compare_exact(
    source: Option<&BTreeMap<String, ProfileAggregate>>,
    target: Option<&BTreeMap<String, ProfileAggregate>>,
) -> TypeComparison {
    let empty = BTreeMap::new();
    let source = source.unwrap_or(&empty);
    let target = target.unwrap_or(&empty);
    let mut comparison = TypeComparison::default();
    for (name, source) in source {
        let Some(target) = target.get(name) else {
            if source.total_count > 0 {
                comparison.record(difference("profile_name_missing", name, Some(source), None));
            }
            continue;
        };
        if source.total_count != target.total_count {
            comparison.record(difference(
                "profile_total_count_mismatch",
                name,
                Some(source),
                Some(target),
            ));
        } else if source.slow_thresholds.is_disjoint(&target.slow_thresholds) {
            comparison.record(difference(
                "profile_slow_threshold_no_match",
                name,
                Some(source),
                Some(target),
            ));
        }
    }
    for (name, target) in target {
        if target.total_count > 0 && !source.contains_key(name) {
            comparison.record(difference(
                "profile_unexpected_name",
                name,
                None,
                Some(target),
            ));
        }
    }
    comparison
}

fn compare_source_positive_exists(
    record_type: &str,
    source: Option<&BTreeMap<String, ProfileAggregate>>,
    target: Option<&BTreeMap<String, ProfileAggregate>>,
    all_target: &ProfileRecords,
    rules: &ProfileByTypeRules,
) -> TypeComparison {
    let mut comparison = TypeComparison::default();
    let Some(source) = source else {
        return comparison;
    };
    for (name, source) in source {
        if source.total_count > 0 && !target.is_some_and(|entries| entries.contains_key(name)) {
            let entirely_missing = !all_target.iter().any(|(target_type, entries)| {
                equivalent_profile_types(record_type, target_type)
                    && entries
                        .keys()
                        .any(|target_name| equivalent_names(record_type, name, target_name))
            });
            if rules.allows_target_missing(record_type, name) && entirely_missing {
                continue;
            }
            comparison.record(difference(
                "profile_required_name_missing",
                name,
                Some(source),
                None,
            ));
        }
    }
    comparison
}

pub(super) fn source_positive_metric_is_target_missing(
    source_path: &Path,
    target_path: &Path,
    rules: &ProfileByTypeRules,
    record_type: &str,
    name: &str,
) -> Result<bool> {
    let source = parse(source_path, ProcessOutputCaptureSide::Source, rules)?;
    let target = parse(target_path, ProcessOutputCaptureSide::Target, rules)?;
    let source_positive = source.iter().any(|(observed_type, entries)| {
        equivalent_profile_types(record_type, observed_type)
            && entries.iter().any(|(source_name, aggregate)| {
                aggregate.total_count > 0 && equivalent_names(record_type, name, source_name)
            })
    });
    let target_present = target.iter().any(|(observed_type, entries)| {
        equivalent_profile_types(record_type, observed_type)
            && entries
                .keys()
                .any(|target_name| equivalent_names(record_type, name, target_name))
    });
    Ok(source_positive && !target_present)
}

fn difference(
    classification: &'static str,
    name: &str,
    source: Option<&ProfileAggregate>,
    target: Option<&ProfileAggregate>,
) -> ProfileDifferenceDetail {
    ProfileDifferenceDetail {
        classification,
        name: name.to_string(),
        observed_type: None,
        source_total_count: source.map(|value| value.total_count),
        target_total_count: target.map(|value| value.total_count),
        source_slow_thresholds: source.map(slow_thresholds),
        target_slow_thresholds: target.map(slow_thresholds),
    }
}

fn slow_thresholds(value: &ProfileAggregate) -> Vec<u64> {
    value.slow_thresholds.iter().copied().collect()
}

fn add_total_count(
    aggregate: &mut ProfileAggregate,
    object: &Map<String, Value>,
    side: ProcessOutputCaptureSide,
    path: &Path,
    line: usize,
) -> Result<()> {
    let total_count = required_u64(object, "total_count", side, path, line)?;
    aggregate.total_count = aggregate
        .total_count
        .checked_add(total_count)
        .with_context(|| {
            format!(
                "{} profile output {} line {} total_count overflowed",
                side_name(side),
                path.display(),
                line
            )
        })?;
    Ok(())
}

fn required_string(
    object: &Map<String, Value>,
    field: &str,
    side: ProcessOutputCaptureSide,
    path: &Path,
    line: usize,
) -> Result<String> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    value.map(str::to_string).with_context(|| {
        format!(
            "{} profile output {} line {} selected record has no non-empty string {field}",
            side_name(side),
            path.display(),
            line
        )
    })
}

fn required_u64(
    object: &Map<String, Value>,
    field: &str,
    side: ProcessOutputCaptureSide,
    path: &Path,
    line: usize,
) -> Result<u64> {
    let value = object.get(field).and_then(parse_u64);
    value.with_context(|| {
        format!(
            "{} profile output {} line {} selected record has no unsigned-integer {field}",
            side_name(side),
            path.display(),
            line
        )
    })
}

fn parse_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn optional_u64(
    object: &Map<String, Value>,
    field: &str,
    side: ProcessOutputCaptureSide,
    path: &Path,
    line: usize,
) -> Result<Option<u64>> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    parse_u64(value).map(Some).with_context(|| {
        format!(
            "{} profile output {} line {} selected record has no unsigned integer {field}",
            side_name(side),
            path.display(),
            line
        )
    })
}

fn side_name(side: ProcessOutputCaptureSide) -> &'static str {
    match side {
        ProcessOutputCaptureSide::Source => "source",
        ProcessOutputCaptureSide::Target => "target",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_output::{
        ProfileTargetMissingAllowance, ProfileTargetMissingEmitterEvidence,
    };

    #[test]
    fn source_positive_ignores_source_records_without_slow_threshold() {
        let rules = ProfileByTypeRules {
            exact_total_count: Vec::new(),
            source_positive_exists: vec!["MC".to_string()],
            allow_target_missing: Vec::new(),
        };
        let result = compare_bytes(
            br#"2026-09-01 {"type":"MC","name":"3110","sockSize":20,"busySize":0}
2026-09-01 {"type":"MC","name":"15138","sockSize":24,"busySize":0}
2026-09-01 {"type":"MC","name":"15138","slowThreshold":50,"total_count":18}
"#,
            br#"2026-09-01 {"type":"MC","name":"15138","slowThreshold":50}
"#,
            &rules,
        );

        assert!(result.passed);
        assert_eq!(result.classification, "equal");
    }

    #[test]
    fn reports_one_example_and_complete_count_per_mismatched_type() {
        let rules = ProfileByTypeRules {
            exact_total_count: vec!["RPC_SERVICE_WHOLE".to_string()],
            source_positive_exists: vec!["MC".to_string(), "HTTP".to_string()],
            allow_target_missing: Vec::new(),
        };
        let result = compare_bytes(
            br#"2026-09-01 {"type":"HTTP","name":"a","slowThreshold":50,"total_count":1}
2026-09-01 {"type":"HTTP","name":"b","slowThreshold":50,"total_count":2}
2026-09-01 {"type":"MC","name":"11211","slowThreshold":50,"total_count":3}
2026-09-01 {"type":"RPC_SERVICE_WHOLE","name":"getConfig","slowThreshold":200,"total_count":12}
"#,
            br#"2026-09-01 {"type":"RPC_SERVICE_WHOLE","name":"getConfig","slowThreshold":200,"total_count":11}
"#,
            &rules,
        );

        assert!(!result.passed);
        assert_eq!(result.classification, "profile_mismatch");
        let detail = result.detail.unwrap();
        assert_eq!(detail.compared_type_count, 3);
        assert_eq!(detail.mismatched_type_count, 3);
        assert_eq!(detail.total_difference_count, 4);
        assert_eq!(
            detail
                .types
                .iter()
                .map(|value| (value.record_type.as_str(), value.difference_count))
                .collect::<Vec<_>>(),
            vec![("HTTP", 2), ("MC", 1), ("RPC_SERVICE_WHOLE", 1)]
        );
        assert_eq!(detail.types[0].example.name, "a");
        assert_eq!(detail.types[1].example.name, "11211");
        assert_eq!(detail.types[2].example.name, "getConfig");
        let evidence = serde_json::to_value(&detail).unwrap();
        assert_eq!(evidence["compared_type_count"], 3);
        assert_eq!(evidence["mismatched_type_count"], 3);
        assert_eq!(evidence["total_difference_count"], 4);
        assert_eq!(evidence["types"][0]["type"], "HTTP");
        assert_eq!(evidence["types"][0]["policy"], "source_positive_exists");
        assert_eq!(evidence["types"][0]["difference_count"], 2);
        assert_eq!(
            evidence["types"][0]["example"]["classification"],
            "profile_required_name_missing"
        );
    }

    #[test]
    fn allows_evidenced_source_positive_metric_to_be_missing_from_target() {
        let rules = ProfileByTypeRules {
            exact_total_count: Vec::new(),
            source_positive_exists: vec!["HTTP".to_string()],
            allow_target_missing: vec![ProfileTargetMissingAllowance {
                metric: "HTTP.http://api.example.com/path".to_string(),
                source_revision: "0123456789abcdef".to_string(),
                dependency_path: vec![
                    "com.example:client-core:2.4.1".to_string(),
                    "com.vendor:telemetry:1.8.0".to_string(),
                ],
                emitter_evidence: ProfileTargetMissingEmitterEvidence {
                    inspected_paths: vec![
                        "pom.xml".to_string(),
                        "vendor/src/com/vendor/telemetry/TelemetryInitializer.java".to_string(),
                    ],
                    description: "TelemetryInitializer independently emits this request without affecting source behavior"
                        .to_string(),
                },
            }],
        };
        let result = compare_bytes(
            br#"2026-09-01 {"type":"HTTP","name":"all_http://api.example.com/path","slowThreshold":200,"total_count":5}
2026-09-01 {"type":"HTTP","name":"http://api.example.com/path","slowThreshold":50,"total_count":5}
"#,
            br#"2026-09-01 {"type":"HTTP","name":"target-only.example.com","slowThreshold":50,"total_count":8}
"#,
            &rules,
        );

        assert!(result.passed);
        assert_eq!(result.classification, "equal");
    }

    #[test]
    fn http_allowance_does_not_hide_a_partially_present_logical_interaction() {
        let rules = http_allowance_rules();
        let result = compare_bytes(
            br#"2026-09-01 {"type":"HTTP","name":"all_http://api.example.com/path","slowThreshold":200,"total_count":5}
2026-09-01 {"type":"HTTP","name":"http://api.example.com/path","slowThreshold":50,"total_count":5}
"#,
            br#"2026-09-01 {"type":"HTTP","name":"http://api.example.com/path","slowThreshold":50,"total_count":5}
"#,
            &rules,
        );

        assert!(!result.passed);
        assert_eq!(result.detail.unwrap().total_difference_count, 1);
    }

    #[test]
    fn motan_aliases_are_checked_independently_but_reported_as_one_type() {
        let rules = ProfileByTypeRules::default();
        let result = compare_bytes(
            br#"2026-09-01 {"type":"RPC_SERVICE_CLIENT_V2","name":"Example.call()","slowThreshold":200,"total_count":2}
2026-09-01 {"type":"RPC_SERVICE_CLIENT_REAL_V2","name":"Example.call()","slowThreshold":200,"total_count":2}
"#,
            b"",
            &rules,
        );

        assert!(!result.passed);
        let detail = result.detail.unwrap();
        assert_eq!(detail.compared_type_count, 3);
        assert_eq!(detail.mismatched_type_count, 1);
        assert_eq!(detail.total_difference_count, 2);
        assert_eq!(detail.types[0].record_type, "RPC_SERVICE_CLIENT");
        assert_eq!(detail.types[0].difference_count, 2);
        assert_eq!(
            detail.types[0].example.observed_type.as_deref(),
            Some("RPC_SERVICE_CLIENT_REAL_V2")
        );
    }

    #[test]
    fn motan_allowance_requires_the_whole_logical_interaction_to_be_absent() {
        let mut rules = ProfileByTypeRules::default();
        let mut allowance = http_allowance_rules().allow_target_missing.remove(0);
        allowance.metric = "RPC_SERVICE_CLIENT.Example.call()".to_string();
        rules.allow_target_missing.push(allowance);
        let result = compare_bytes(
            br#"2026-09-01 {"type":"RPC_SERVICE_CLIENT_V2","name":"Example.call()","slowThreshold":200,"total_count":2}
"#,
            br#"2026-09-01 {"type":"RPC_SERVICE_CLIENT_REAL","name":"Example.call()","slowThreshold":200,"total_count":2}
"#,
            &rules,
        );

        assert!(!result.passed);
        assert_eq!(result.detail.unwrap().total_difference_count, 1);
    }

    #[test]
    fn exact_treats_missing_groups_as_zero_in_both_directions() {
        let rules = ProfileByTypeRules {
            exact_total_count: vec!["RPC_SERVICE_WHOLE".to_string()],
            source_positive_exists: Vec::new(),
            allow_target_missing: Vec::new(),
        };
        let result = compare_bytes(
            br#"2026-09-01 {"type":"RPC_SERVICE_WHOLE","name":"source_zero","slowThreshold":200,"total_count":0}
"#,
            br#"2026-09-01 {"type":"RPC_SERVICE_WHOLE","name":"target_zero","slowThreshold":500,"total_count":0}
"#,
            &rules,
        );

        assert!(result.passed);
        assert_eq!(result.classification, "equal");
    }

    #[test]
    fn exact_still_rejects_missing_positive_groups_in_both_directions() {
        let rules = ProfileByTypeRules {
            exact_total_count: vec!["RPC_SERVICE_WHOLE".to_string()],
            source_positive_exists: Vec::new(),
            allow_target_missing: Vec::new(),
        };
        let result = compare_bytes(
            br#"2026-09-01 {"type":"RPC_SERVICE_WHOLE","name":"source_positive","slowThreshold":200,"total_count":1}
"#,
            br#"2026-09-01 {"type":"RPC_SERVICE_WHOLE","name":"target_positive","slowThreshold":200,"total_count":1}
"#,
            &rules,
        );

        assert!(!result.passed);
        let detail = result.detail.unwrap();
        assert_eq!(detail.total_difference_count, 2);
        assert_eq!(detail.types[0].difference_count, 2);
        assert_eq!(detail.types[0].example.name, "source_positive");
        assert_eq!(
            detail.types[0].example.classification,
            "profile_name_missing"
        );
    }

    fn compare_bytes(
        source_bytes: &[u8],
        target_bytes: &[u8],
        rules: &ProfileByTypeRules,
    ) -> ComparisonOutcome {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source.log");
        let target = root.path().join("target.log");
        std::fs::write(&source, source_bytes).unwrap();
        std::fs::write(&target, target_bytes).unwrap();
        compare(&source, &target, rules).unwrap()
    }

    fn http_allowance_rules() -> ProfileByTypeRules {
        ProfileByTypeRules {
            exact_total_count: Vec::new(),
            source_positive_exists: vec!["HTTP".to_string()],
            allow_target_missing: vec![ProfileTargetMissingAllowance {
                metric: "HTTP.http://api.example.com/path".to_string(),
                source_revision: "0123456789abcdef".to_string(),
                dependency_path: vec![
                    "com.example:client-core:2.4.1".to_string(),
                    "com.vendor:telemetry:1.8.0".to_string(),
                ],
                emitter_evidence: ProfileTargetMissingEmitterEvidence {
                    inspected_paths: vec![
                        "pom.xml".to_string(),
                        "vendor/src/com/vendor/telemetry/TelemetryInitializer.java".to_string(),
                    ],
                    description: "TelemetryInitializer independently emits this request without affecting source behavior"
                        .to_string(),
                },
            }],
        }
    }
}
