use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use super::pattern::path_pattern_matches;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonSourceMatch {
    #[default]
    Before,
    BeforeOrAfter,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComparisonVerificationPolicy {
    #[serde(default)]
    pub source_match: ComparisonSourceMatch,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct ResponseRules {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::replay) dynamic: BTreeMap<String, Vec<DynamicResponseRule>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::replay) unordered: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::replay) motan: BTreeMap<String, MotanResponseRule>,
    #[serde(default, skip_serializing_if = "ComparisonResponseRules::is_empty")]
    pub(in crate::replay) comparison: ComparisonResponseRules,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct ComparisonResponseRules {
    #[serde(default)]
    pub(in crate::replay) source_match: ComparisonSourceMatch,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::replay) counter: BTreeMap<String, Vec<CounterResponseRule>>,
}

impl ComparisonResponseRules {
    fn is_empty(&self) -> bool {
        self.source_match == ComparisonSourceMatch::Before
            && self.counter.values().all(Vec::is_empty)
    }
}

impl ResponseRules {
    pub(in crate::replay) fn is_empty(&self) -> bool {
        self.dynamic.values().all(Vec::is_empty)
            && self.unordered.values().all(Vec::is_empty)
            && self.motan.is_empty()
            && self.comparison.is_empty()
    }

    pub(in crate::replay) fn matching_replay_fields(
        &self,
        method: &str,
        path: &str,
    ) -> Vec<ResponseField> {
        matching_dynamic_fields(&self.dynamic, method, path)
            .chain(matching_pointer_fields(
                &self.unordered,
                ResponseRuleKind::Unordered,
                method,
                path,
            ))
            .collect()
    }

    pub(in crate::replay) fn matching_comparison_fields(
        &self,
        method: &str,
        path: &str,
    ) -> Vec<ResponseField> {
        self.matching_replay_fields(method, path)
            .into_iter()
            .chain(matching_counter_fields(
                &self.comparison.counter,
                method,
                path,
            ))
            .collect()
    }

    pub(in crate::replay) fn matching_motan_rules(
        &self,
        method: &str,
        path: &str,
    ) -> Vec<MotanResponseRuleMatch> {
        self.motan
            .iter()
            .filter_map(|(api, rule)| {
                let (candidate_method, candidate_path) = parse_api(api).ok()?;
                (candidate_method.eq_ignore_ascii_case(method)
                    && path_pattern_matches(candidate_path, path))
                .then(|| MotanResponseRuleMatch {
                    id: motan_response_rule_id(api),
                    api: api.clone(),
                    protocol: rule.protocol,
                    unordered_paths: rule.unordered_paths.clone(),
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MotanBodyProtocol {
    Protobuf,
    Hessian2,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct ProtobufFieldPath(pub Vec<u32>);

impl ProtobufFieldPath {
    pub fn display_path(&self) -> String {
        self.0
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct MotanResponseRule {
    pub(in crate::replay) protocol: MotanBodyProtocol,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) unordered_paths: Vec<MotanUnorderedPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ProtobufUnorderedPath {
    pub field_path: ProtobufFieldPath,
    pub display_path: String,
    pub element_type: ProtobufRepeatedElementType,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct Hessian2ValuePath(pub Vec<String>);

impl Hessian2ValuePath {
    pub fn display_path(&self) -> String {
        if self.0.is_empty() {
            return "$".to_string();
        }
        self.0
            .iter()
            .fold(String::from("$"), |mut display, segment| {
                if segment == "*" {
                    display.push_str("[*]");
                } else {
                    display.push('.');
                    display.push_str(segment);
                }
                display
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Hessian2UnorderedPath {
    pub value_path: Hessian2ValuePath,
    pub display_path: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum MotanUnorderedPath {
    Protobuf(ProtobufUnorderedPath),
    Hessian2(Hessian2UnorderedPath),
}

impl<'de> Deserialize<'de> for MotanUnorderedPath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let has_field_path = value.get("field_path").is_some();
        let has_value_path = value.get("value_path").is_some();
        match (has_field_path, has_value_path) {
            (true, false) => serde_json::from_value(value)
                .map(Self::Protobuf)
                .map_err(D::Error::custom),
            (false, true) => serde_json::from_value(value)
                .map(Self::Hessian2)
                .map_err(D::Error::custom),
            (true, true) => Err(D::Error::custom(
                "Motan unordered path cannot contain both field_path and value_path",
            )),
            (false, false) => Err(D::Error::custom(
                "Motan unordered path requires field_path or value_path",
            )),
        }
    }
}

impl MotanUnorderedPath {
    pub fn protocol(&self) -> MotanBodyProtocol {
        match self {
            Self::Protobuf(_) => MotanBodyProtocol::Protobuf,
            Self::Hessian2(_) => MotanBodyProtocol::Hessian2,
        }
    }

    pub fn display_path(&self) -> &str {
        match self {
            Self::Protobuf(path) => &path.display_path,
            Self::Hessian2(path) => &path.display_path,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProtobufRepeatedElementType {
    String,
    Message,
    Int32,
    Int64,
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Bool,
    Enum,
    Fixed32,
    Sfixed32,
    Float,
    Fixed64,
    Sfixed64,
    Double,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::replay) struct MotanResponseRuleMatch {
    pub(in crate::replay) id: String,
    pub(in crate::replay) api: String,
    pub(in crate::replay) protocol: MotanBodyProtocol,
    pub(in crate::replay) unordered_paths: Vec<MotanUnorderedPath>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseRuleKind {
    Dynamic,
    Unordered,
    Counter,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DynamicResponseMechanism {
    Timestamp,
    Duration,
    Uuid,
    Random,
    Nonce,
    RandomSalt,
    DynamicDerived,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct DynamicResponseRule {
    pub(in crate::replay) pointer: String,
    pub(in crate::replay) mechanisms: Vec<DynamicResponseMechanism>,
    pub(in crate::replay) source_evidence: String,
    pub(in crate::replay) source_example: String,
    pub(in crate::replay) target_example: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct CounterResponseRule {
    pub(in crate::replay) pointer: String,
    pub(in crate::replay) source_evidence: String,
    pub(in crate::replay) source_example: String,
    pub(in crate::replay) target_example: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseField {
    pub id: String,
    pub api: String,
    pub pointer: String,
    pub kind: ResponseRuleKind,
}

pub(in crate::replay) fn validate_response_rules(rules: &ResponseRules) -> Result<()> {
    let mut locations = Vec::new();
    validate_dynamic_rule_map(&rules.dynamic, &mut locations)?;
    validate_pointer_rule_map(
        ResponseRuleKind::Unordered,
        &rules.unordered,
        &mut locations,
    )?;
    validate_motan_rule_map(&rules.motan)?;
    validate_counter_rule_map(&rules.comparison.counter, &mut locations)?;
    for motan_api in rules.motan.keys() {
        let (_, motan_path) = parse_api(motan_api)?;
        for (method, path, pointer, kind) in &locations {
            ensure!(
                !method.eq_ignore_ascii_case("MOTAN") || !path_patterns_overlap(motan_path, path),
                "Motan response rule {motan_api:?} overlaps JSON response rule {kind:?} MOTAN {path} at {pointer}"
            );
        }
    }
    for (index, left) in locations.iter().enumerate() {
        for right in locations.iter().skip(index + 1) {
            if left.0.eq_ignore_ascii_case(right.0)
                && response_locations_overlap(left.2, right.2)
                && path_patterns_overlap(left.1, right.1)
            {
                anyhow::bail!(
                    "overlapping response rules select the same JSON subtree: {:?} {} {} at {} and {:?} {} {} at {}",
                    left.3,
                    left.0,
                    left.1,
                    left.2,
                    right.3,
                    right.0,
                    right.1,
                    right.2
                );
            }
        }
    }
    Ok(())
}

pub(in crate::replay) fn response_rule_ids(rules: &ResponseRules) -> Vec<String> {
    dynamic_rule_ids(&rules.dynamic)
        .chain(pointer_rule_ids(
            &rules.unordered,
            ResponseRuleKind::Unordered,
        ))
        .chain(counter_rule_ids(&rules.comparison.counter))
        .chain(rules.motan.keys().map(|api| motan_response_rule_id(api)))
        .collect()
}

pub(in crate::replay) fn motan_response_rule_id(api: &str) -> String {
    format!("response:motan:{api}")
}

pub(in crate::replay) fn response_rule_id(
    kind: ResponseRuleKind,
    api: &str,
    pointer: &str,
) -> String {
    let (namespace, kind) = match kind {
        ResponseRuleKind::Dynamic => ("response", "dynamic"),
        ResponseRuleKind::Unordered => ("response", "unordered"),
        ResponseRuleKind::Counter => ("response:comparison", "counter"),
    };
    format!("{namespace}:{kind}:{api}:{pointer}")
}

pub(in crate::replay) fn parse_api(api: &str) -> Result<(&str, &str)> {
    let (method, path) = api
        .split_once(' ')
        .ok_or_else(|| anyhow::anyhow!("response rule API must use 'METHOD /path': {api:?}"))?;
    ensure!(
        !method.is_empty() && !path.is_empty() && !path.contains(char::is_whitespace),
        "response rule API must use canonical 'METHOD /path': {api:?}"
    );
    ensure!(
        path.starts_with('/'),
        "response rule API path must be absolute: {api:?}"
    );
    Ok((method, path))
}

pub(in crate::replay) fn validate_json_pointer(pointer: &str) -> Result<()> {
    ensure!(
        pointer.starts_with('/') && pointer.len() > 1,
        "response field must use a non-root JSON Pointer: {pointer:?}"
    );
    let bytes = pointer.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            ensure!(
                bytes
                    .get(index + 1)
                    .is_some_and(|byte| matches!(byte, b'0' | b'1')),
                "JSON Pointer contains an invalid '~' escape: {pointer:?}"
            );
            index += 1;
        }
        index += 1;
    }
    Ok(())
}

type RuleLocation<'a> = (&'a str, &'a str, &'a str, ResponseRuleKind);

fn validate_dynamic_rule_map<'a>(
    rules: &'a BTreeMap<String, Vec<DynamicResponseRule>>,
    locations: &mut Vec<RuleLocation<'a>>,
) -> Result<()> {
    for (api, fields) in rules {
        let (method, path) = validate_rule_api(api, fields.is_empty())?;
        let mut unique = BTreeSet::new();
        for field in fields {
            validate_json_pointer(&field.pointer)?;
            ensure!(
                unique.insert(field.pointer.as_str()),
                "response rule API {api:?} repeats JSON Pointer {:?}",
                field.pointer
            );
            validate_dynamic_rule(field)?;
            locations.push((method, path, &field.pointer, ResponseRuleKind::Dynamic));
        }
    }
    Ok(())
}

fn validate_pointer_rule_map<'a>(
    kind: ResponseRuleKind,
    rules: &'a BTreeMap<String, Vec<String>>,
    locations: &mut Vec<RuleLocation<'a>>,
) -> Result<()> {
    for (api, pointers) in rules {
        let (method, path) = validate_rule_api(api, pointers.is_empty())?;
        let mut unique = BTreeSet::new();
        for pointer in pointers {
            validate_json_pointer(pointer)?;
            ensure!(
                unique.insert(pointer),
                "response rule API {api:?} repeats JSON Pointer {pointer:?}"
            );
            locations.push((method, path, pointer, kind));
        }
    }
    Ok(())
}

fn validate_counter_rule_map<'a>(
    rules: &'a BTreeMap<String, Vec<CounterResponseRule>>,
    locations: &mut Vec<RuleLocation<'a>>,
) -> Result<()> {
    for (api, fields) in rules {
        let (method, path) = validate_rule_api(api, fields.is_empty())?;
        let mut unique = BTreeSet::new();
        for field in fields {
            validate_json_pointer(&field.pointer)?;
            ensure!(
                unique.insert(field.pointer.as_str()),
                "response rule API {api:?} repeats JSON Pointer {:?}",
                field.pointer
            );
            validate_counter_rule(field)?;
            locations.push((method, path, &field.pointer, ResponseRuleKind::Counter));
        }
    }
    Ok(())
}

fn validate_motan_rule_map(rules: &BTreeMap<String, MotanResponseRule>) -> Result<()> {
    const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;
    const MAX_PATHS: usize = 32;
    const MAX_PATH_DEPTH: usize = 32;

    let mut routes = Vec::new();
    for (api, rule) in rules {
        let (method, path) = parse_api(api)?;
        ensure!(
            method == "MOTAN",
            "Motan response rule API method must be MOTAN: {api:?}"
        );
        ensure!(
            rule.unordered_paths.len() <= MAX_PATHS,
            "Motan response rule API {api:?} selects more than {MAX_PATHS} unordered paths"
        );
        let mut unique_protobuf = BTreeSet::new();
        let mut unique_hessian2 = BTreeSet::new();
        let mut unique_display = BTreeSet::new();
        for unordered_path in &rule.unordered_paths {
            ensure!(
                unordered_path.protocol() == rule.protocol,
                "Motan response rule API {api:?} has an unordered path for a different body protocol"
            );
            validate_audit_text(unordered_path.display_path(), "display_path", 512)?;
            ensure!(
                unordered_path
                    .display_path()
                    .chars()
                    .any(|character| character.is_alphabetic() || character == '_'),
                "Motan response rule API {api:?} requires a semantic display_path"
            );
            ensure!(
                unique_display.insert(unordered_path.display_path()),
                "Motan response rule API {api:?} repeats display_path {:?}",
                unordered_path.display_path()
            );
            match unordered_path {
                MotanUnorderedPath::Protobuf(unordered_path) => {
                    let field_path = &unordered_path.field_path;
                    ensure!(
                        !field_path.0.is_empty() && field_path.0.len() <= MAX_PATH_DEPTH,
                        "Motan response rule API {api:?} has an empty or over-deep protobuf field path"
                    );
                    ensure!(
                        field_path
                            .0
                            .iter()
                            .all(|number| (1..=MAX_FIELD_NUMBER).contains(number)),
                        "Motan response rule API {api:?} has an invalid protobuf field number"
                    );
                    ensure!(
                        unique_protobuf.insert(field_path),
                        "Motan response rule API {api:?} repeats protobuf field path {:?}",
                        field_path.0
                    );
                    ensure!(
                        unordered_path.display_path != field_path.display_path(),
                        "Motan response rule API {api:?} protobuf field path {:?} requires a semantic display_path",
                        field_path.0
                    );
                }
                MotanUnorderedPath::Hessian2(unordered_path) => {
                    let value_path = &unordered_path.value_path;
                    ensure!(
                        value_path.0.len() <= MAX_PATH_DEPTH,
                        "Motan response rule API {api:?} has an over-deep Hessian2 value path"
                    );
                    for segment in &value_path.0 {
                        validate_audit_text(segment, "Hessian2 value path segment", 256)?;
                    }
                    ensure!(
                        unique_hessian2.insert(value_path),
                        "Motan response rule API {api:?} repeats Hessian2 value path {:?}",
                        value_path.0
                    );
                }
            }
        }
        routes.push((api.as_str(), path));
    }
    for (index, (left_api, left_path)) in routes.iter().enumerate() {
        for (right_api, right_path) in routes.iter().skip(index + 1) {
            ensure!(
                !path_patterns_overlap(left_path, right_path),
                "overlapping Motan response rules select the same API: {left_api:?} and {right_api:?}"
            );
        }
    }
    Ok(())
}

fn validate_rule_api(api: &str, empty: bool) -> Result<(&str, &str)> {
    let (method, path) = parse_api(api)?;
    ensure!(
        method == method.to_ascii_uppercase(),
        "response rule API method must use uppercase canonical form: {api:?}"
    );
    ensure!(
        !empty,
        "response rule API {api:?} must select at least one JSON Pointer"
    );
    Ok((method, path))
}

fn validate_dynamic_rule(rule: &DynamicResponseRule) -> Result<()> {
    ensure!(
        !rule.mechanisms.is_empty(),
        "dynamic response rule {} requires at least one mechanism",
        rule.pointer
    );
    let mechanisms = rule.mechanisms.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        mechanisms.len() == rule.mechanisms.len(),
        "dynamic response rule {} repeats a mechanism",
        rule.pointer
    );
    ensure!(
        !mechanisms.contains(&DynamicResponseMechanism::DynamicDerived) || mechanisms.len() > 1,
        "dynamic response rule {} uses dynamic_derived without its underlying mechanism",
        rule.pointer
    );
    validate_audit_text(&rule.source_evidence, "source_evidence", 512)?;
    validate_audit_text(&rule.source_example, "source_example", 1024)?;
    validate_audit_text(&rule.target_example, "target_example", 1024)?;
    ensure!(
        rule.source_example != rule.target_example,
        "dynamic response rule {} requires different source and target examples",
        rule.pointer
    );
    Ok(())
}

fn validate_counter_rule(rule: &CounterResponseRule) -> Result<()> {
    validate_audit_text(&rule.source_evidence, "source_evidence", 512)?;
    validate_audit_text(&rule.source_example, "source_example", 1024)?;
    validate_audit_text(&rule.target_example, "target_example", 1024)?;
    ensure!(
        rule.source_example != rule.target_example,
        "counter response rule {} requires different source and target examples",
        rule.pointer
    );
    Ok(())
}

fn validate_audit_text(value: &str, label: &str, max_len: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty(),
        "response rule {label} must not be blank"
    );
    ensure!(
        !value.contains(['\r', '\n']),
        "response rule {label} must be a single line"
    );
    ensure!(
        value.len() <= max_len,
        "response rule {label} exceeds {max_len} bytes"
    );
    Ok(())
}

fn matching_dynamic_fields<'a>(
    rules: &'a BTreeMap<String, Vec<DynamicResponseRule>>,
    method: &'a str,
    path: &'a str,
) -> impl Iterator<Item = ResponseField> + 'a {
    rules
        .iter()
        .filter_map(move |(api, fields)| {
            let (candidate_method, candidate_path) = parse_api(api).ok()?;
            (candidate_method.eq_ignore_ascii_case(method)
                && path_pattern_matches(candidate_path, path))
            .then_some((api, fields))
        })
        .flat_map(move |(api, fields)| {
            fields.iter().map(move |field| ResponseField {
                id: response_rule_id(ResponseRuleKind::Dynamic, api, &field.pointer),
                api: api.clone(),
                pointer: field.pointer.clone(),
                kind: ResponseRuleKind::Dynamic,
            })
        })
}

fn matching_pointer_fields<'a>(
    rules: &'a BTreeMap<String, Vec<String>>,
    kind: ResponseRuleKind,
    method: &'a str,
    path: &'a str,
) -> impl Iterator<Item = ResponseField> + 'a {
    rules
        .iter()
        .filter_map(move |(api, pointers)| {
            let (candidate_method, candidate_path) = parse_api(api).ok()?;
            (candidate_method.eq_ignore_ascii_case(method)
                && path_pattern_matches(candidate_path, path))
            .then_some((api, pointers))
        })
        .flat_map(move |(api, pointers)| {
            pointers.iter().map(move |pointer| ResponseField {
                id: response_rule_id(kind, api, pointer),
                api: api.clone(),
                pointer: pointer.clone(),
                kind,
            })
        })
}

fn matching_counter_fields<'a>(
    rules: &'a BTreeMap<String, Vec<CounterResponseRule>>,
    method: &'a str,
    path: &'a str,
) -> impl Iterator<Item = ResponseField> + 'a {
    rules
        .iter()
        .filter_map(move |(api, fields)| {
            let (candidate_method, candidate_path) = parse_api(api).ok()?;
            (candidate_method.eq_ignore_ascii_case(method)
                && path_pattern_matches(candidate_path, path))
            .then_some((api, fields))
        })
        .flat_map(move |(api, fields)| {
            fields.iter().map(move |field| ResponseField {
                id: response_rule_id(ResponseRuleKind::Counter, api, &field.pointer),
                api: api.clone(),
                pointer: field.pointer.clone(),
                kind: ResponseRuleKind::Counter,
            })
        })
}

fn dynamic_rule_ids(
    rules: &BTreeMap<String, Vec<DynamicResponseRule>>,
) -> impl Iterator<Item = String> + '_ {
    rules.iter().flat_map(|(api, fields)| {
        fields
            .iter()
            .map(move |field| response_rule_id(ResponseRuleKind::Dynamic, api, &field.pointer))
    })
}

fn pointer_rule_ids(
    rules: &BTreeMap<String, Vec<String>>,
    kind: ResponseRuleKind,
) -> impl Iterator<Item = String> + '_ {
    rules.iter().flat_map(move |(api, pointers)| {
        pointers
            .iter()
            .map(move |pointer| response_rule_id(kind, api, pointer))
    })
}

fn counter_rule_ids(
    rules: &BTreeMap<String, Vec<CounterResponseRule>>,
) -> impl Iterator<Item = String> + '_ {
    rules.iter().flat_map(|(api, fields)| {
        fields
            .iter()
            .map(move |field| response_rule_id(ResponseRuleKind::Counter, api, &field.pointer))
    })
}

pub(crate) fn response_locations_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn path_patterns_overlap(left: &str, right: &str) -> bool {
    let left = left.split('/').collect::<Vec<_>>();
    let right = right.split('/').collect::<Vec<_>>();
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left == &"*" || right == "*" || left == &right)
}

#[cfg(test)]
#[path = "response/motan_tests.rs"]
mod motan_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn dynamic(pointer: &str) -> DynamicResponseRule {
        DynamicResponseRule {
            pointer: pointer.to_string(),
            mechanisms: vec![DynamicResponseMechanism::Uuid],
            source_evidence: "src/token.rs:issue_token".to_string(),
            source_example: "<redacted source UUID>".to_string(),
            target_example: "<redacted target UUID>".to_string(),
        }
    }

    fn counter(pointer: &str) -> CounterResponseRule {
        CounterResponseRule {
            pointer: pointer.to_string(),
            source_evidence: "src/user.rs:load live count".to_string(),
            source_example: "100".to_string(),
            target_example: "101".to_string(),
        }
    }

    #[test]
    fn matches_exact_and_segment_pattern_apis() {
        let rules = ResponseRules {
            dynamic: BTreeMap::from([
                (
                    "GET /api/resource/token".to_string(),
                    vec![dynamic("/content")],
                ),
                ("GET /api/sessions/*".to_string(), vec![dynamic("/data/id")]),
            ]),
            unordered: BTreeMap::new(),
            motan: BTreeMap::new(),
            comparison: ComparisonResponseRules::default(),
        };

        assert_eq!(
            rules
                .matching_replay_fields("GET", "/api/resource/token")
                .iter()
                .map(|field| field.pointer.as_str())
                .collect::<Vec<_>>(),
            vec!["/content"]
        );
        assert_eq!(
            rules
                .matching_replay_fields("GET", "/api/sessions/42")
                .iter()
                .map(|field| field.pointer.as_str())
                .collect::<Vec<_>>(),
            vec!["/data/id"]
        );
    }

    #[test]
    fn rejects_overlapping_routes_for_the_same_pointer() {
        let rules = ResponseRules {
            dynamic: BTreeMap::from([
                ("GET /api/sessions/*".to_string(), vec![dynamic("/content")]),
                (
                    "GET /api/sessions/current".to_string(),
                    vec![dynamic("/content")],
                ),
            ]),
            unordered: BTreeMap::new(),
            motan: BTreeMap::new(),
            comparison: ComparisonResponseRules::default(),
        };

        assert!(validate_response_rules(&rules).is_err());
    }

    #[test]
    fn rejects_overlapping_dynamic_and_unordered_subtrees() {
        let rules = ResponseRules {
            dynamic: BTreeMap::from([(
                "GET /api/resource".to_string(),
                vec![dynamic("/content/0/id")],
            )]),
            unordered: BTreeMap::from([(
                "GET /api/resource".to_string(),
                vec!["/content".to_string()],
            )]),
            motan: BTreeMap::new(),
            comparison: ComparisonResponseRules::default(),
        };

        assert!(validate_response_rules(&rules).is_err());
    }

    #[test]
    fn rejects_overlapping_replay_and_comparison_subtrees() {
        let rules = ResponseRules {
            dynamic: BTreeMap::from([(
                "GET /api/users/show".to_string(),
                vec![dynamic("/followers_count")],
            )]),
            comparison: ComparisonResponseRules {
                counter: BTreeMap::from([(
                    "GET /api/users/show".to_string(),
                    vec![counter("/followers_count")],
                )]),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(validate_response_rules(&rules).is_err());
    }

    #[test]
    fn rejects_overlapping_motan_and_json_response_rules() {
        let rules = ResponseRules {
            unordered: BTreeMap::from([(
                "MOTAN /rpc/example".to_string(),
                vec!["/content".to_string()],
            )]),
            motan: BTreeMap::from([(
                "MOTAN /rpc/*".to_string(),
                MotanResponseRule {
                    protocol: MotanBodyProtocol::Protobuf,
                    unordered_paths: Vec::new(),
                },
            )]),
            ..Default::default()
        };

        assert!(validate_response_rules(&rules).is_err());
    }

    #[test]
    fn matches_and_identifies_unordered_fields() {
        let rules = ResponseRules {
            dynamic: BTreeMap::new(),
            unordered: BTreeMap::from([(
                "GET /api/config/ansible_facts".to_string(),
                vec!["/general/sudo_users".to_string()],
            )]),
            motan: BTreeMap::new(),
            comparison: ComparisonResponseRules::default(),
        };

        let fields = rules.matching_replay_fields("GET", "/api/config/ansible_facts");

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].kind, ResponseRuleKind::Unordered);
        assert_eq!(
            fields[0].id,
            "response:unordered:GET /api/config/ansible_facts:/general/sudo_users"
        );
    }

    #[test]
    fn counter_fields_are_available_only_to_comparison_matching() {
        let rules = ResponseRules {
            comparison: ComparisonResponseRules {
                counter: BTreeMap::from([(
                    "GET /api/users/show".to_string(),
                    vec![counter("/followers_count")],
                )]),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(
            rules
                .matching_replay_fields("GET", "/api/users/show")
                .is_empty()
        );
        let fields = rules.matching_comparison_fields("GET", "/api/users/show");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].kind, ResponseRuleKind::Counter);
        assert_eq!(
            fields[0].id,
            "response:comparison:counter:GET /api/users/show:/followers_count"
        );
    }

    #[test]
    fn rejects_invalid_json_pointer_escape() {
        assert!(validate_json_pointer("/content/~2").is_err());
    }

    #[test]
    fn rejects_dynamic_rules_without_auditable_evidence() {
        let rules = ResponseRules {
            dynamic: BTreeMap::from([(
                "GET /api/resource".to_string(),
                vec![DynamicResponseRule {
                    pointer: "/content".to_string(),
                    mechanisms: vec![DynamicResponseMechanism::Uuid],
                    source_evidence: "src/token.rs:issue_token".to_string(),
                    source_example: "<same>".to_string(),
                    target_example: "<same>".to_string(),
                }],
            )]),
            unordered: BTreeMap::new(),
            motan: BTreeMap::new(),
            comparison: ComparisonResponseRules::default(),
        };

        assert!(validate_response_rules(&rules).is_err());
    }

    #[test]
    fn rejects_legacy_pointer_only_dynamic_rules() {
        let error = serde_yaml::from_str::<ResponseRules>(
            r#"
dynamic:
  "GET /api/resource":
    - /content
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("invalid type"));
    }
}
