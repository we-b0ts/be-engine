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

impl ComparisonVerificationPolicy {
    fn is_empty(&self) -> bool {
        self.source_match == ComparisonSourceMatch::Before
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct ResponseSettings {
    #[serde(
        default,
        skip_serializing_if = "ComparisonVerificationPolicy::is_empty"
    )]
    pub(in crate::replay) comparison: ComparisonVerificationPolicy,
}

impl ResponseSettings {
    pub(in crate::replay) fn is_empty(&self) -> bool {
        self.comparison.is_empty()
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct ResponseRules {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::replay) json: BTreeMap<String, JsonResponseRules>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::replay) protobuf: BTreeMap<String, ProtobufResponseRules>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::replay) hessian2: BTreeMap<String, Hessian2ResponseRules>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct JsonResponseRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) timestamp: Vec<GeneratedResponseRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) duration: Vec<GeneratedResponseRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) uuid: Vec<GeneratedResponseRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) random: Vec<GeneratedResponseRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) unordered: Vec<JsonUnorderedResponseRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) counter: Vec<CounterResponseRule>,
}

impl JsonResponseRules {
    fn is_empty(&self) -> bool {
        self.timestamp.is_empty()
            && self.duration.is_empty()
            && self.uuid.is_empty()
            && self.random.is_empty()
            && self.unordered.is_empty()
            && self.counter.is_empty()
    }

    pub(in crate::replay) fn generated(
        &self,
    ) -> impl Iterator<Item = (ResponseRuleKind, &GeneratedResponseRule)> {
        self.timestamp
            .iter()
            .map(|rule| (ResponseRuleKind::Timestamp, rule))
            .chain(
                self.duration
                    .iter()
                    .map(|rule| (ResponseRuleKind::Duration, rule)),
            )
            .chain(self.uuid.iter().map(|rule| (ResponseRuleKind::Uuid, rule)))
            .chain(
                self.random
                    .iter()
                    .map(|rule| (ResponseRuleKind::Random, rule)),
            )
    }

    pub(in crate::replay) fn generated_for_kind(
        &self,
        kind: ResponseRuleKind,
    ) -> Option<&Vec<GeneratedResponseRule>> {
        match kind {
            ResponseRuleKind::Timestamp => Some(&self.timestamp),
            ResponseRuleKind::Duration => Some(&self.duration),
            ResponseRuleKind::Uuid => Some(&self.uuid),
            ResponseRuleKind::Random => Some(&self.random),
            ResponseRuleKind::Unordered | ResponseRuleKind::Counter => None,
        }
    }

    pub(in crate::replay) fn generated_for_kind_mut(
        &mut self,
        kind: ResponseRuleKind,
    ) -> Option<&mut Vec<GeneratedResponseRule>> {
        match kind {
            ResponseRuleKind::Timestamp => Some(&mut self.timestamp),
            ResponseRuleKind::Duration => Some(&mut self.duration),
            ResponseRuleKind::Uuid => Some(&mut self.uuid),
            ResponseRuleKind::Random => Some(&mut self.random),
            ResponseRuleKind::Unordered | ResponseRuleKind::Counter => None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct ProtobufResponseRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) unordered: Vec<ProtobufUnorderedPath>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct Hessian2ResponseRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) unordered: Vec<Hessian2UnorderedPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) unordered_joined_string: Vec<Hessian2JoinedStringPath>,
}

impl ResponseRules {
    pub(in crate::replay) fn is_empty(&self) -> bool {
        self.json.is_empty() && self.protobuf.is_empty() && self.hessian2.is_empty()
    }

    pub(in crate::replay) fn matching_replay_fields(
        &self,
        method: &str,
        path: &str,
    ) -> Vec<ResponseField> {
        matching_json_rules(&self.json, method, path)
            .flat_map(|(api, rules)| {
                rules
                    .generated()
                    .map(move |(kind, field)| response_field(kind, api, &field.pointer))
                    .chain(rules.unordered.iter().map(move |field| {
                        response_field(ResponseRuleKind::Unordered, api, &field.pointer)
                    }))
            })
            .collect()
    }

    pub(in crate::replay) fn matching_comparison_fields(
        &self,
        method: &str,
        path: &str,
    ) -> Vec<ResponseField> {
        self.matching_replay_fields(method, path)
            .into_iter()
            .chain(
                matching_json_rules(&self.json, method, path).flat_map(|(api, rules)| {
                    rules.counter.iter().map(move |field| {
                        response_field(ResponseRuleKind::Counter, api, &field.pointer)
                    })
                }),
            )
            .collect()
    }

    pub(in crate::replay) fn matching_motan_rules(
        &self,
        method: &str,
        path: &str,
    ) -> Vec<MotanResponseRuleMatch> {
        matching_body_rules(&self.protobuf, method, path)
            .map(|(api, rules)| MotanResponseRuleMatch {
                id: motan_response_rule_id(api),
                api: api.clone(),
                protocol: MotanBodyProtocol::Protobuf,
                unordered_paths: rules
                    .unordered
                    .iter()
                    .cloned()
                    .map(MotanUnorderedPath::Protobuf)
                    .collect(),
                unordered_joined_string_paths: Vec::new(),
            })
            .chain(
                matching_body_rules(&self.hessian2, method, path).map(|(api, rules)| {
                    MotanResponseRuleMatch {
                        id: motan_response_rule_id(api),
                        api: api.clone(),
                        protocol: MotanBodyProtocol::Hessian2,
                        unordered_paths: rules
                            .unordered
                            .iter()
                            .cloned()
                            .map(MotanUnorderedPath::Hessian2)
                            .collect(),
                        unordered_joined_string_paths: rules.unordered_joined_string.clone(),
                    }
                }),
            )
            .collect()
    }

    pub(in crate::replay) fn configured_motan_rule(
        &self,
        api: &str,
    ) -> Option<MotanResponseRuleMatch> {
        self.protobuf
            .get(api)
            .map(|rules| MotanResponseRuleMatch {
                id: motan_response_rule_id(api),
                api: api.to_string(),
                protocol: MotanBodyProtocol::Protobuf,
                unordered_paths: rules
                    .unordered
                    .iter()
                    .cloned()
                    .map(MotanUnorderedPath::Protobuf)
                    .collect(),
                unordered_joined_string_paths: Vec::new(),
            })
            .or_else(|| {
                self.hessian2.get(api).map(|rules| MotanResponseRuleMatch {
                    id: motan_response_rule_id(api),
                    api: api.to_string(),
                    protocol: MotanBodyProtocol::Hessian2,
                    unordered_paths: rules
                        .unordered
                        .iter()
                        .cloned()
                        .map(MotanUnorderedPath::Hessian2)
                        .collect(),
                    unordered_joined_string_paths: rules.unordered_joined_string.clone(),
                })
            })
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ProtobufUnorderedPath {
    pub field_path: ProtobufFieldPath,
    pub display_path: String,
    pub element_type: ProtobufRepeatedElementType,
    pub source_evidence: String,
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
    pub source_evidence: String,
}

/// Selects a Hessian2 **String** field whose value is a set joined into one
/// string (for example `"alice,bob,carol"`). The string is split on
/// `separator` and compared as a multiset, so element order is ignored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Hessian2JoinedStringPath {
    pub value_path: Hessian2ValuePath,
    pub display_path: String,
    pub separator: String,
    pub source_evidence: String,
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
    pub(in crate::replay) unordered_joined_string_paths: Vec<Hessian2JoinedStringPath>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseRuleKind {
    Timestamp,
    Duration,
    Uuid,
    Random,
    Unordered,
    Counter,
}

impl ResponseRuleKind {
    pub(in crate::replay) fn is_generated(self) -> bool {
        matches!(
            self,
            Self::Timestamp | Self::Duration | Self::Uuid | Self::Random
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct GeneratedResponseRule {
    pub(in crate::replay) pointer: String,
    pub(in crate::replay) source_evidence: String,
    pub(in crate::replay) source_example: String,
    pub(in crate::replay) target_example: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct JsonUnorderedResponseRule {
    pub(in crate::replay) pointer: String,
    pub(in crate::replay) source_evidence: String,
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
    validate_json_rule_map(&rules.json, &mut locations)?;
    validate_protobuf_rule_map(&rules.protobuf)?;
    validate_hessian2_rule_map(&rules.hessian2)?;
    validate_body_protocol_routes(rules)?;
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
    rules
        .json
        .iter()
        .flat_map(|(api, rules)| {
            rules
                .generated()
                .map(move |(kind, field)| response_rule_id(kind, api, &field.pointer))
                .chain(rules.unordered.iter().map(move |field| {
                    response_rule_id(ResponseRuleKind::Unordered, api, &field.pointer)
                }))
                .chain(rules.counter.iter().map(move |field| {
                    response_rule_id(ResponseRuleKind::Counter, api, &field.pointer)
                }))
        })
        .chain(
            rules
                .protobuf
                .keys()
                .chain(rules.hessian2.keys())
                .map(|api| motan_response_rule_id(api)),
        )
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
        ResponseRuleKind::Timestamp => ("response", "timestamp"),
        ResponseRuleKind::Duration => ("response", "duration"),
        ResponseRuleKind::Uuid => ("response", "uuid"),
        ResponseRuleKind::Random => ("response", "random"),
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

fn validate_json_rule_map<'a>(
    rules: &'a BTreeMap<String, JsonResponseRules>,
    locations: &mut Vec<RuleLocation<'a>>,
) -> Result<()> {
    for (api, rules) in rules {
        let (method, path) = validate_rule_api(api)?;
        ensure!(
            method != "MOTAN",
            "JSON response rule API cannot use the MOTAN carrier: {api:?}"
        );
        ensure!(
            !rules.is_empty(),
            "JSON response rule API {api:?} must select at least one rule"
        );
        let mut unique_generated = BTreeSet::new();
        for (kind, field) in rules.generated() {
            validate_json_pointer(&field.pointer)?;
            ensure!(
                unique_generated.insert(field.pointer.as_str()),
                "generated response rules for API {api:?} repeat JSON Pointer {:?}",
                field.pointer
            );
            validate_generated_rule(kind, field)?;
            locations.push((method, path, &field.pointer, kind));
        }
        let mut unique_unordered = BTreeSet::new();
        for field in &rules.unordered {
            validate_json_pointer(&field.pointer)?;
            ensure!(
                unique_unordered.insert(field.pointer.as_str()),
                "unordered response rule API {api:?} repeats JSON Pointer {:?}",
                field.pointer
            );
            validate_audit_text(&field.source_evidence, "source_evidence", 512)?;
            locations.push((method, path, &field.pointer, ResponseRuleKind::Unordered));
        }
        let mut unique_counter = BTreeSet::new();
        for field in &rules.counter {
            validate_json_pointer(&field.pointer)?;
            ensure!(
                unique_counter.insert(field.pointer.as_str()),
                "counter response rule API {api:?} repeats JSON Pointer {:?}",
                field.pointer
            );
            validate_counter_rule(field)?;
            locations.push((method, path, &field.pointer, ResponseRuleKind::Counter));
        }
    }
    Ok(())
}

fn validate_protobuf_rule_map(rules: &BTreeMap<String, ProtobufResponseRules>) -> Result<()> {
    const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;
    const MAX_PATHS: usize = 32;
    const MAX_PATH_DEPTH: usize = 32;

    for (api, rule) in rules {
        let (method, _) = validate_rule_api(api)?;
        ensure!(
            method == "MOTAN",
            "protobuf response rule API method must be MOTAN: {api:?}"
        );
        ensure!(
            rule.unordered.len() <= MAX_PATHS,
            "protobuf response rule API {api:?} selects more than {MAX_PATHS} unordered paths"
        );
        let mut unique_protobuf = BTreeSet::new();
        let mut unique_display = BTreeSet::new();
        for unordered_path in &rule.unordered {
            validate_audit_text(&unordered_path.display_path, "display_path", 512)?;
            validate_audit_text(&unordered_path.source_evidence, "source_evidence", 512)?;
            ensure!(
                unordered_path
                    .display_path
                    .chars()
                    .any(|character| character.is_alphabetic() || character == '_'),
                "protobuf response rule API {api:?} requires a semantic display_path"
            );
            ensure!(
                unique_display.insert(&unordered_path.display_path),
                "protobuf response rule API {api:?} repeats display_path {:?}",
                unordered_path.display_path
            );
            let field_path = &unordered_path.field_path;
            ensure!(
                !field_path.0.is_empty() && field_path.0.len() <= MAX_PATH_DEPTH,
                "protobuf response rule API {api:?} has an empty or over-deep field path"
            );
            ensure!(
                field_path
                    .0
                    .iter()
                    .all(|number| (1..=MAX_FIELD_NUMBER).contains(number)),
                "protobuf response rule API {api:?} has an invalid field number"
            );
            ensure!(
                unique_protobuf.insert(field_path),
                "protobuf response rule API {api:?} repeats field path {:?}",
                field_path.0
            );
            ensure!(
                unordered_path.display_path != field_path.display_path(),
                "protobuf response rule API {api:?} field path {:?} requires a semantic display_path",
                field_path.0
            );
        }
    }
    Ok(())
}

fn validate_hessian2_rule_map(rules: &BTreeMap<String, Hessian2ResponseRules>) -> Result<()> {
    const MAX_PATHS: usize = 32;
    const MAX_PATH_DEPTH: usize = 32;

    for (api, rule) in rules {
        let (method, _) = validate_rule_api(api)?;
        ensure!(
            method == "MOTAN",
            "Hessian2 response rule API method must be MOTAN: {api:?}"
        );
        ensure!(
            rule.unordered.len() <= MAX_PATHS,
            "Hessian2 response rule API {api:?} selects more than {MAX_PATHS} unordered paths"
        );
        ensure!(
            rule.unordered_joined_string.len() <= MAX_PATHS,
            "Hessian2 response rule API {api:?} selects more than {MAX_PATHS} unordered joined-string paths"
        );
        let mut unique_hessian2 = BTreeSet::new();
        let mut unique_display = BTreeSet::new();
        for unordered_path in &rule.unordered {
            validate_hessian2_value_path(api, &unordered_path.value_path, MAX_PATH_DEPTH)?;
            validate_semantic_display_path(api, &unordered_path.display_path)?;
            validate_audit_text(&unordered_path.source_evidence, "source_evidence", 512)?;
            ensure!(
                unique_display.insert(&unordered_path.display_path),
                "Hessian2 response rule API {api:?} repeats display_path {:?}",
                unordered_path.display_path
            );
            ensure!(
                unique_hessian2.insert(&unordered_path.value_path),
                "Hessian2 response rule API {api:?} repeats value path {:?}",
                unordered_path.value_path.0
            );
        }
        let mut unique_joined_string = BTreeSet::new();
        for joined in &rule.unordered_joined_string {
            validate_hessian2_value_path(api, &joined.value_path, MAX_PATH_DEPTH)?;
            ensure!(
                !joined.separator.is_empty(),
                "Hessian2 response rule API {api:?} has a joined-string path with an empty separator"
            );
            validate_audit_text(&joined.separator, "Hessian2 joined-string separator", 16)?;
            validate_semantic_display_path(api, &joined.display_path)?;
            validate_audit_text(&joined.source_evidence, "source_evidence", 512)?;
            ensure!(
                unique_display.insert(&joined.display_path),
                "Hessian2 response rule API {api:?} repeats display_path {:?}",
                joined.display_path
            );
            ensure!(
                unique_joined_string.insert(&joined.value_path),
                "Hessian2 response rule API {api:?} repeats joined-string value path {:?}",
                joined.value_path.0
            );
            ensure!(
                unique_hessian2.insert(&joined.value_path),
                "Hessian2 response rule API {api:?} joins the same value path {:?} as an unordered list path",
                joined.value_path.0
            );
        }
    }
    Ok(())
}

fn validate_body_protocol_routes(rules: &ResponseRules) -> Result<()> {
    let routes = rules
        .protobuf
        .keys()
        .map(|api| ("protobuf", api))
        .chain(rules.hessian2.keys().map(|api| ("hessian2", api)))
        .map(|(protocol, api)| {
            let (_, path) = parse_api(api)?;
            Ok((protocol, api.as_str(), path))
        })
        .collect::<Result<Vec<_>>>()?;
    for (index, (left_protocol, left_api, left_path)) in routes.iter().enumerate() {
        for (right_protocol, right_api, right_path) in routes.iter().skip(index + 1) {
            ensure!(
                !path_patterns_overlap(left_path, right_path),
                "overlapping body protocol response rules select the same API: {left_protocol} {left_api:?} and {right_protocol} {right_api:?}"
            );
        }
    }
    Ok(())
}

fn validate_hessian2_value_path(
    api: &str,
    value_path: &Hessian2ValuePath,
    max_depth: usize,
) -> Result<()> {
    ensure!(
        value_path.0.len() <= max_depth,
        "Hessian2 response rule API {api:?} has an over-deep value path"
    );
    for segment in &value_path.0 {
        validate_audit_text(segment, "Hessian2 value path segment", 256)?;
    }
    Ok(())
}

fn validate_semantic_display_path(api: &str, display_path: &str) -> Result<()> {
    validate_audit_text(display_path, "display_path", 512)?;
    ensure!(
        display_path
            .chars()
            .any(|character| character.is_alphabetic() || character == '_'),
        "Hessian2 response rule API {api:?} requires a semantic display_path"
    );
    Ok(())
}

fn validate_rule_api(api: &str) -> Result<(&str, &str)> {
    let (method, path) = parse_api(api)?;
    ensure!(
        method == method.to_ascii_uppercase(),
        "response rule API method must use uppercase canonical form: {api:?}"
    );
    Ok((method, path))
}

fn validate_generated_rule(kind: ResponseRuleKind, rule: &GeneratedResponseRule) -> Result<()> {
    ensure!(
        kind.is_generated(),
        "generated response rule has an invalid kind"
    );
    validate_audit_text(&rule.source_evidence, "source_evidence", 512)?;
    validate_audit_text(&rule.source_example, "source_example", 1024)?;
    validate_audit_text(&rule.target_example, "target_example", 1024)?;
    ensure!(
        rule.source_example != rule.target_example,
        "{kind:?} response rule {} requires different source and target examples",
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

fn matching_json_rules<'a>(
    rules: &'a BTreeMap<String, JsonResponseRules>,
    method: &'a str,
    path: &'a str,
) -> impl Iterator<Item = (&'a String, &'a JsonResponseRules)> + 'a {
    rules.iter().filter_map(move |(api, rules)| {
        let (candidate_method, candidate_path) = parse_api(api).ok()?;
        (candidate_method.eq_ignore_ascii_case(method)
            && path_pattern_matches(candidate_path, path))
        .then_some((api, rules))
    })
}

fn matching_body_rules<'a, T>(
    rules: &'a BTreeMap<String, T>,
    method: &'a str,
    path: &'a str,
) -> impl Iterator<Item = (&'a String, &'a T)> + 'a {
    rules.iter().filter_map(move |(api, rules)| {
        let (candidate_method, candidate_path) = parse_api(api).ok()?;
        (candidate_method.eq_ignore_ascii_case(method)
            && path_pattern_matches(candidate_path, path))
        .then_some((api, rules))
    })
}

fn response_field(kind: ResponseRuleKind, api: &str, pointer: &str) -> ResponseField {
    ResponseField {
        id: response_rule_id(kind, api, pointer),
        api: api.to_string(),
        pointer: pointer.to_string(),
        kind,
    }
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
#[path = "response/tests.rs"]
mod tests;
