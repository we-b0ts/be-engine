use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use super::pattern::path_pattern_matches;

mod body_validation;
mod joined_string;
use crate::replay::policy::json_pointer;
mod json_validation;
mod jwt;
mod time_rule;
use json_validation::validate_json_rule_map;
pub use jwt::{ResponseJwtAlgorithm, ResponseJwtKeySource, ResponseJwtRule};
pub use time_rule::{
    ResponseDurationUnit, ResponseTimeRule, ResponseTimestampFormat, ResponseTimestampMode,
};

pub(crate) use json_pointer::response_locations_overlap;
pub(crate) use json_pointer::{
    response_pointer_matches, select_json_pointers, validate_json_pointer,
};

use body_validation::{
    validate_body_codec_routes, validate_hessian2_rule_map, validate_protobuf_rule_map,
};
pub(crate) use joined_string::JsonJoinedStringResponseRule;
use joined_string::validate_separator;
pub use joined_string::{
    Hessian2JoinedStringPath, ProtobufJoinedStringFieldType, ProtobufJoinedStringPath,
    ResponseBodyJoinedStringPath,
};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponseRules {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) headers: super::response_headers::ResponseHeaderRules,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) json: BTreeMap<String, JsonResponseRules>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) protobuf: BTreeMap<String, ProtobufResponseRules>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) hessian2: BTreeMap<String, Hessian2ResponseRules>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) docx: BTreeMap<String, DocxResponseRules>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JsonResponseRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) jwt: Vec<ResponseJwtRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) timestamp: Vec<GeneratedResponseRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) duration: Vec<GeneratedResponseRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) uuid: Vec<GeneratedResponseRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) random: Vec<GeneratedResponseRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) unordered: Vec<JsonUnorderedResponseRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) unordered_joined_string: Vec<JsonJoinedStringResponseRule>,
}

impl JsonResponseRules {
    fn is_empty(&self) -> bool {
        self.jwt.is_empty()
            && self.timestamp.is_empty()
            && self.duration.is_empty()
            && self.uuid.is_empty()
            && self.random.is_empty()
            && self.unordered.is_empty()
            && self.unordered_joined_string.is_empty()
    }

    pub(crate) fn generated(
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

    pub(crate) fn generated_for_kind(
        &self,
        kind: ResponseRuleKind,
    ) -> Option<&Vec<GeneratedResponseRule>> {
        match kind {
            ResponseRuleKind::Timestamp => Some(&self.timestamp),
            ResponseRuleKind::Duration => Some(&self.duration),
            ResponseRuleKind::Uuid => Some(&self.uuid),
            ResponseRuleKind::Random => Some(&self.random),
            ResponseRuleKind::Jwt
            | ResponseRuleKind::Unordered
            | ResponseRuleKind::UnorderedJoinedString => None,
        }
    }

    pub(crate) fn generated_for_kind_mut(
        &mut self,
        kind: ResponseRuleKind,
    ) -> Option<&mut Vec<GeneratedResponseRule>> {
        match kind {
            ResponseRuleKind::Timestamp => Some(&mut self.timestamp),
            ResponseRuleKind::Duration => Some(&mut self.duration),
            ResponseRuleKind::Uuid => Some(&mut self.uuid),
            ResponseRuleKind::Random => Some(&mut self.random),
            ResponseRuleKind::Jwt
            | ResponseRuleKind::Unordered
            | ResponseRuleKind::UnorderedJoinedString => None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtobufResponseRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) unordered: Vec<ProtobufUnorderedPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) unordered_joined_string: Vec<ProtobufJoinedStringPath>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hessian2ResponseRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) unordered: Vec<Hessian2UnorderedPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) unordered_joined_string: Vec<Hessian2JoinedStringPath>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DocxResponseRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) timestamp: Vec<DocxTimestampRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocxTimestampRule {
    pub part: String,
    pub element: String,
    pub format: ResponseTimestampFormat,
    pub source_evidence: String,
    pub source_example: String,
    pub target_example: String,
}

impl ResponseRules {
    pub(crate) fn is_empty(&self) -> bool {
        self.headers.is_empty()
            && self.json.is_empty()
            && self.protobuf.is_empty()
            && self.hessian2.is_empty()
            && self.docx.is_empty()
    }

    pub(crate) fn matching_replay_fields(&self, method: &str, path: &str) -> Vec<ResponseField> {
        matching_json_rules(&self.json, method, path)
            .flat_map(|(api, rules)| {
                rules
                    .generated()
                    .map(move |(kind, field)| {
                        let mut selected = response_field(kind, api, &field.pointer, None);
                        selected.time = ResponseTimeRule::from_options_with_mode(
                            Some(kind),
                            field.unit,
                            field.format,
                            field.time,
                        )
                        .expect("response time settings were validated on load");
                        selected
                    })
                    .chain(rules.jwt.iter().map(move |rule| {
                        let mut field =
                            response_field(ResponseRuleKind::Jwt, api, &rule.pointer, None);
                        field.jwt = Some(rule.clone());
                        field
                    }))
                    .chain(rules.unordered.iter().map(move |field| {
                        response_field(ResponseRuleKind::Unordered, api, &field.pointer, None)
                    }))
                    .chain(rules.unordered_joined_string.iter().map(move |field| {
                        response_field(
                            ResponseRuleKind::UnorderedJoinedString,
                            api,
                            &field.pointer,
                            Some(&field.separator),
                        )
                    }))
            })
            .collect()
    }

    pub(crate) fn matching_response_body_rules(
        &self,
        method: &str,
        path: &str,
    ) -> Vec<ResponseBodyRuleMatch> {
        matching_body_rules(&self.protobuf, method, path)
            .map(|(api, rules)| ResponseBodyRuleMatch {
                id: response_body_rule_id(api),
                api: api.clone(),
                codec: ResponseBodyCodec::Protobuf,
                unordered_paths: rules
                    .unordered
                    .iter()
                    .cloned()
                    .map(ResponseBodyUnorderedPath::Protobuf)
                    .collect(),
                unordered_joined_string_paths: rules
                    .unordered_joined_string
                    .iter()
                    .cloned()
                    .map(ResponseBodyJoinedStringPath::Protobuf)
                    .collect(),
                docx_timestamps: Vec::new(),
            })
            .chain(
                matching_body_rules(&self.hessian2, method, path).map(|(api, rules)| {
                    ResponseBodyRuleMatch {
                        id: response_body_rule_id(api),
                        api: api.clone(),
                        codec: ResponseBodyCodec::Hessian2,
                        unordered_paths: rules
                            .unordered
                            .iter()
                            .cloned()
                            .map(ResponseBodyUnorderedPath::Hessian2)
                            .collect(),
                        unordered_joined_string_paths: rules
                            .unordered_joined_string
                            .iter()
                            .cloned()
                            .map(ResponseBodyJoinedStringPath::Hessian2)
                            .collect(),
                        docx_timestamps: Vec::new(),
                    }
                }),
            )
            .chain(
                matching_body_rules(&self.docx, method, path).map(|(api, rules)| {
                    ResponseBodyRuleMatch {
                        id: response_body_rule_id(api),
                        api: api.clone(),
                        codec: ResponseBodyCodec::Docx,
                        unordered_paths: Vec::new(),
                        unordered_joined_string_paths: Vec::new(),
                        docx_timestamps: rules.timestamp.clone(),
                    }
                }),
            )
            .collect()
    }

    pub(crate) fn configured_response_body_rule(&self, api: &str) -> Option<ResponseBodyRuleMatch> {
        self.protobuf
            .get(api)
            .map(|rules| ResponseBodyRuleMatch {
                id: response_body_rule_id(api),
                api: api.to_string(),
                codec: ResponseBodyCodec::Protobuf,
                unordered_paths: rules
                    .unordered
                    .iter()
                    .cloned()
                    .map(ResponseBodyUnorderedPath::Protobuf)
                    .collect(),
                unordered_joined_string_paths: rules
                    .unordered_joined_string
                    .iter()
                    .cloned()
                    .map(ResponseBodyJoinedStringPath::Protobuf)
                    .collect(),
                docx_timestamps: Vec::new(),
            })
            .or_else(|| {
                self.hessian2.get(api).map(|rules| ResponseBodyRuleMatch {
                    id: response_body_rule_id(api),
                    api: api.to_string(),
                    codec: ResponseBodyCodec::Hessian2,
                    unordered_paths: rules
                        .unordered
                        .iter()
                        .cloned()
                        .map(ResponseBodyUnorderedPath::Hessian2)
                        .collect(),
                    unordered_joined_string_paths: rules
                        .unordered_joined_string
                        .iter()
                        .cloned()
                        .map(ResponseBodyJoinedStringPath::Hessian2)
                        .collect(),
                    docx_timestamps: Vec::new(),
                })
            })
            .or_else(|| {
                self.docx.get(api).map(|rules| ResponseBodyRuleMatch {
                    id: response_body_rule_id(api),
                    api: api.to_string(),
                    codec: ResponseBodyCodec::Docx,
                    unordered_paths: Vec::new(),
                    unordered_joined_string_paths: Vec::new(),
                    docx_timestamps: rules.timestamp.clone(),
                })
            })
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBodyCodec {
    #[default]
    Unknown,
    Json,
    Protobuf,
    Hessian2,
    Docx,
    ExactBytes,
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum ResponseBodyUnorderedPath {
    Protobuf(ProtobufUnorderedPath),
    Hessian2(Hessian2UnorderedPath),
}

impl<'de> Deserialize<'de> for ResponseBodyUnorderedPath {
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
                "response-body unordered path cannot contain both field_path and value_path",
            )),
            (false, false) => Err(D::Error::custom(
                "response-body unordered path requires field_path or value_path",
            )),
        }
    }
}

impl ResponseBodyUnorderedPath {
    pub fn codec(&self) -> ResponseBodyCodec {
        match self {
            Self::Protobuf(_) => ResponseBodyCodec::Protobuf,
            Self::Hessian2(_) => ResponseBodyCodec::Hessian2,
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
pub(crate) struct ResponseBodyRuleMatch {
    pub(crate) id: String,
    pub(crate) api: String,
    pub(crate) codec: ResponseBodyCodec,
    pub(crate) unordered_paths: Vec<ResponseBodyUnorderedPath>,
    pub(crate) unordered_joined_string_paths: Vec<ResponseBodyJoinedStringPath>,
    pub(crate) docx_timestamps: Vec<DocxTimestampRule>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseRuleKind {
    Timestamp,
    Duration,
    Uuid,
    Random,
    Jwt,
    Unordered,
    UnorderedJoinedString,
}

impl ResponseRuleKind {
    pub(crate) fn is_generated(self) -> bool {
        matches!(
            self,
            Self::Timestamp | Self::Duration | Self::Uuid | Self::Random | Self::Jwt
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratedResponseRule {
    pub(crate) pointer: String,
    pub(crate) source_evidence: String,
    pub(crate) source_example: String,
    pub(crate) target_example: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) unit: Option<ResponseDurationUnit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) format: Option<ResponseTimestampFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) time: Option<ResponseTimestampMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct JsonUnorderedResponseRule {
    pub(crate) pointer: String,
    pub(crate) source_evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseField {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<ResponseJwtRule>,
    pub id: String,
    pub api: String,
    pub pointer: String,
    pub kind: ResponseRuleKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<ResponseTimeRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub separator: Option<String>,
}

pub(crate) fn validate_response_rules(rules: &ResponseRules) -> Result<()> {
    super::response_headers::validate(&rules.headers)?;
    let mut locations = Vec::new();
    validate_json_rule_map(&rules.json, &mut locations)?;
    validate_protobuf_rule_map(&rules.protobuf)?;
    validate_hessian2_rule_map(&rules.hessian2)?;
    validate_docx_rule_map(&rules.docx)?;
    validate_body_codec_routes(rules)?;
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

#[cfg(test)]
pub(crate) fn response_rule_ids(rules: &ResponseRules) -> Vec<String> {
    rules
        .json
        .iter()
        .flat_map(|(api, rules)| {
            rules
                .generated()
                .map(move |(kind, field)| response_rule_id(kind, api, &field.pointer))
                .chain(rules.jwt.iter().map(move |rule| rule.id(api)))
                .chain(rules.unordered.iter().map(move |field| {
                    response_rule_id(ResponseRuleKind::Unordered, api, &field.pointer)
                }))
                .chain(rules.unordered_joined_string.iter().map(move |field| {
                    response_rule_id(ResponseRuleKind::UnorderedJoinedString, api, &field.pointer)
                }))
        })
        .chain(
            rules
                .protobuf
                .keys()
                .chain(rules.hessian2.keys())
                .chain(rules.docx.keys())
                .map(|api| response_body_rule_id(api)),
        )
        .chain(
            rules
                .headers
                .iter()
                .flat_map(|(api, rules)| rules.iter().map(move |rule| rule.id(api))),
        )
        .collect()
}

pub(crate) fn response_body_rule_id(api: &str) -> String {
    format!("response:body:{api}")
}

pub(crate) fn response_rule_id(kind: ResponseRuleKind, api: &str, pointer: &str) -> String {
    let (namespace, kind) = match kind {
        ResponseRuleKind::Timestamp => ("response", "timestamp"),
        ResponseRuleKind::Duration => ("response", "duration"),
        ResponseRuleKind::Uuid => ("response", "uuid"),
        ResponseRuleKind::Random => ("response", "random"),
        ResponseRuleKind::Jwt => ("response", "jwt"),
        ResponseRuleKind::Unordered => ("response", "unordered"),
        ResponseRuleKind::UnorderedJoinedString => ("response", "unordered_joined_string"),
    };
    format!("{namespace}:{kind}:{api}:{pointer}")
}

pub(crate) fn parse_api(api: &str) -> Result<(&str, &str)> {
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

type RuleLocation<'a> = (&'a str, &'a str, &'a str, ResponseRuleKind);

fn validate_docx_rule_map(rules: &BTreeMap<String, DocxResponseRules>) -> Result<()> {
    for (api, rules) in rules {
        validate_rule_api(api)?;
        let mut unique = BTreeSet::new();
        for rule in &rules.timestamp {
            ensure!(
                !rule.part.is_empty()
                    && rule.part.len() <= 256
                    && !rule.part.starts_with('/')
                    && !rule
                        .part
                        .split('/')
                        .any(|segment| segment.is_empty() || segment == "." || segment == ".."),
                "DOCX timestamp part must be a safe relative OPC part name"
            );
            ensure!(
                !rule.element.is_empty()
                    && rule.element.len() <= 128
                    && rule.element.bytes().all(|byte| byte.is_ascii_alphanumeric()
                        || matches!(byte, b':' | b'_' | b'-' | b'.')),
                "DOCX timestamp element must be a qualified XML name"
            );
            ensure!(
                unique.insert((&rule.part, &rule.element)),
                "DOCX response rule API {api:?} repeats timestamp {} in {}",
                rule.element,
                rule.part
            );
            validate_audit_text(&rule.source_evidence, "source_evidence", 512)?;
            validate_audit_text(&rule.source_example, "source_example", 1024)?;
            validate_audit_text(&rule.target_example, "target_example", 1024)?;
            ensure!(
                rule.source_example != rule.target_example,
                "DOCX timestamp rule {} in {} requires different source and target examples",
                rule.element,
                rule.part
            );
        }
    }
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

fn validate_audit_text(value: &str, label: &str, max_len: usize) -> Result<()> {
    if label == "source_evidence" && value.is_empty() {
        return Ok(());
    }
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

fn response_field(
    kind: ResponseRuleKind,
    api: &str,
    pointer: &str,
    separator: Option<&str>,
) -> ResponseField {
    ResponseField {
        jwt: None,
        id: response_rule_id(kind, api, pointer),
        api: api.to_string(),
        pointer: pointer.to_string(),
        kind,
        time: None,
        separator: separator.map(str::to_string),
    }
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
#[path = "response/response_body_tests.rs"]
mod response_body_tests;

#[cfg(test)]
#[path = "response/tests.rs"]
mod tests;

fn validate_generated_rule(kind: ResponseRuleKind, rule: &GeneratedResponseRule) -> Result<()> {
    ResponseTimeRule::from_options_with_mode(Some(kind), rule.unit, rule.format, rule.time)?;
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
