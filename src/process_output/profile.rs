use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead as _, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Map, Value};

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
    let compared_type_count = policies.len();
    let mut types = Vec::new();
    let mut total_difference_count = 0usize;

    for (record_type, policy) in policies {
        let source_records = source.get(record_type);
        let target_records = target.get(record_type);
        let comparison = match policy {
            ProfileByTypePolicy::ExactTotalCount => compare_exact(source_records, target_records),
            ProfileByTypePolicy::SourcePositiveExists => {
                compare_source_positive_exists(source_records, target_records)
            }
        };
        if comparison.difference_count > 0 {
            total_difference_count = total_difference_count
                .checked_add(comparison.difference_count)
                .context("profile comparison difference count overflowed")?;
            types.push(ProfileTypeComparisonDetail {
                record_type: record_type.to_string(),
                policy,
                difference_count: comparison.difference_count,
                example: comparison
                    .example
                    .expect("a nonzero profile difference count must have an example"),
            });
        }
    }

    if !types.is_empty() {
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
            comparison.record(difference("profile_name_missing", name, Some(source), None));
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
        if !source.contains_key(name) {
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
    source: Option<&BTreeMap<String, ProfileAggregate>>,
    target: Option<&BTreeMap<String, ProfileAggregate>>,
) -> TypeComparison {
    let mut comparison = TypeComparison::default();
    let Some(source) = source else {
        return comparison;
    };
    for (name, source) in source {
        if source.total_count > 0 && !target.is_some_and(|entries| entries.contains_key(name)) {
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

fn difference(
    classification: &'static str,
    name: &str,
    source: Option<&ProfileAggregate>,
    target: Option<&ProfileAggregate>,
) -> ProfileDifferenceDetail {
    ProfileDifferenceDetail {
        classification,
        name: name.to_string(),
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

    #[test]
    fn source_positive_ignores_source_records_without_slow_threshold() {
        let rules = ProfileByTypeRules {
            exact_total_count: Vec::new(),
            source_positive_exists: vec!["MC".to_string()],
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
}
