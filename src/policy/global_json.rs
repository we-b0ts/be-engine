//! One format declaration for every decoded JSON payload, independent of carrier.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ClockScope, FieldContract, IdentityFormat, TimeAnchor, TimeRelation, TimestampFormat};

mod template;
pub use template::GlobalTemplateFormat;

pub const GLOBAL_JSON_ID: &str = "global.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonPolicy {
    #[serde(deserialize_with = "super::strict_map::unique_map")]
    pub fields: BTreeMap<String, GlobalField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompiledJsonPolicy {
    pub fields: BTreeMap<String, GlobalField>,
    pub time: super::TimePolicy,
    pub fingerprint: String,
    #[serde(skip)]
    pub(crate) signatures: super::signatures::SignatureRegistry,
}

#[derive(Debug, Clone)]
pub(crate) struct SelectedGlobalField {
    pub(crate) pattern: String,
    pub(crate) pointer: String,
    pub(crate) contract: FieldContract,
    pub(crate) rule_id: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GlobalField {
    Policy(traffic_policy::PolicyDefinition),
    Time {
        formats: Vec<GlobalTimeFormat>,
    },
    Identity {
        formats: Vec<GlobalIdentityFormat>,
    },
    Duration {
        formats: Vec<super::DurationUnit>,
    },
    Url {
        formats: Vec<super::GlobalUrlFormat>,
    },
    Template {
        formats: Vec<GlobalTemplateFormat>,
    },
    Jwt {
        #[serde(
            default = "default_signature",
            skip_serializing_if = "is_default_signature"
        )]
        signature: String,
    },
    Unordered,
}

fn default_signature() -> String {
    "default".into()
}
fn is_default_signature(name: &str) -> bool {
    name == "default"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "TimeFormatDocument", into = "TimeFormatDocument")]
pub struct GlobalTimeFormat {
    pub format: TimestampFormat,
    pub utc_offset: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum TimeFormatDocument {
    Named(TimestampFormat),
    Detailed {
        format: TimestampFormat,
        utc_offset: String,
    },
}

impl From<TimeFormatDocument> for GlobalTimeFormat {
    fn from(value: TimeFormatDocument) -> Self {
        match value {
            TimeFormatDocument::Named(format) => Self {
                format,
                utc_offset: None,
            },
            TimeFormatDocument::Detailed { format, utc_offset } => Self {
                format,
                utc_offset: Some(utc_offset),
            },
        }
    }
}

impl From<GlobalTimeFormat> for TimeFormatDocument {
    fn from(value: GlobalTimeFormat) -> Self {
        match value.utc_offset {
            Some(utc_offset) => Self::Detailed {
                format: value.format,
                utc_offset,
            },
            None => Self::Named(value.format),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "IdentityFormatDocument", into = "IdentityFormatDocument")]
pub struct GlobalIdentityFormat {
    pub prefix: String,
    pub format: IdentityFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum IdentityFormatDocument {
    Named(IdentityFormat),
    Hex {
        #[serde(default)]
        prefix: String,
        hex: usize,
    },
    Base64Url {
        #[serde(default)]
        prefix: String,
        base64url: usize,
    },
    Prefixed {
        prefix: String,
        format: IdentityFormat,
    },
}

impl From<IdentityFormatDocument> for GlobalIdentityFormat {
    fn from(value: IdentityFormatDocument) -> Self {
        match value {
            IdentityFormatDocument::Named(format) => Self {
                prefix: String::new(),
                format,
            },
            IdentityFormatDocument::Hex { prefix, hex } => Self {
                prefix,
                format: IdentityFormat::Hex(hex),
            },
            IdentityFormatDocument::Base64Url { prefix, base64url } => Self {
                prefix,
                format: IdentityFormat::Base64Url(base64url),
            },
            IdentityFormatDocument::Prefixed { prefix, format } => Self { prefix, format },
        }
    }
}

impl From<GlobalIdentityFormat> for IdentityFormatDocument {
    fn from(value: GlobalIdentityFormat) -> Self {
        if value.prefix.is_empty() {
            return Self::Named(value.format);
        }
        match value.format {
            IdentityFormat::Hex(hex) => Self::Hex {
                prefix: value.prefix,
                hex,
            },
            IdentityFormat::Base64Url(base64url) => Self::Base64Url {
                prefix: value.prefix,
                base64url,
            },
            format => Self::Prefixed {
                prefix: value.prefix,
                format,
            },
        }
    }
}

impl GlobalTimeFormat {
    pub fn contract(&self) -> FieldContract {
        FieldContract::Time {
            format: self.format,
            relation: TimeRelation::PreserveOffset,
            anchor: TimeAnchor::Observation,
            utc_offset: self.utc_offset.clone(),
            // Every physical occurrence owns its clock observations; an authored
            // global field declaration does not join unrelated business clocks.
            clock_group: None,
            clock_scope: ClockScope::default(),
        }
    }
}

impl GlobalField {
    pub(crate) fn is_identity(&self) -> bool {
        matches!(self, Self::Identity { .. } | Self::Jwt { .. })
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Policy(definition) => {
                traffic_extensions::policies().prepare_definition(definition)?;
            }
            Self::Time { formats } => {
                ensure!(
                    !formats.is_empty() && formats.len() <= 16,
                    "time requires 1..16 formats"
                );
                for format in formats {
                    let contract = format.contract().time().expect("time contract");
                    ensure!(
                        format.format != TimestampFormat::CalendarDate
                            || format.utc_offset.is_some(),
                        "calendar_date requires an explicit format utc_offset"
                    );
                    ensure!(
                        format.utc_offset.is_none()
                            || matches!(
                                format.format,
                                TimestampFormat::CalendarDate
                                    | TimestampFormat::SqlDatetime
                                    | TimestampFormat::Iso8601Naive
                            ),
                        "only calendar and naive time formats accept utc_offset"
                    );
                    contract.offset()?;
                    let definition = format
                        .contract()
                        .registered_definition(true)
                        .expect("timestamp has a registered implementation");
                    traffic_extensions::policies().prepare_definition(&definition)?;
                }
            }
            Self::Identity { formats } => {
                ensure!(
                    !formats.is_empty() && formats.len() <= 16,
                    "identity requires 1..16 formats"
                );
                for format in formats {
                    ensure!(
                        format.prefix.len() <= 128 && format.prefix.is_ascii(),
                        "identity prefix requires at most 128 ASCII bytes"
                    );
                    match format.format {
                        IdentityFormat::Hex(length) => ensure!(
                            (1..=1024).contains(&length),
                            "identity hex requires 1..1024 characters"
                        ),
                        IdentityFormat::BoundedString(length) => ensure!(
                            (1..=1024).contains(&length),
                            "identity string length requires 1..1024 bytes"
                        ),
                        IdentityFormat::Base64Url(length) => ensure!(
                            (1..=1024).contains(&length),
                            "identity base64url requires 1..1024 characters"
                        ),
                        IdentityFormat::Jwt => anyhow::bail!(
                            "JWT identity syntax is retired; use kind: jwt with a named signatures definition"
                        ),
                        _ => {}
                    }
                    let definition = FieldContract::Identity {
                        prefix: format.prefix.clone(),
                        format: format.format,
                    }
                    .registered_definition(false)
                    .expect("identity has a registered implementation");
                    traffic_extensions::policies().prepare_definition(&definition)?;
                }
            }
            Self::Url { formats } => {
                ensure!(formats.len() == 1, "URL requires one known protocol format")
            }
            Self::Template { formats } => {
                ensure!(
                    !formats.is_empty() && formats.len() <= 16,
                    "template requires 1..16 formats"
                );
                for format in formats {
                    format.validate()?;
                }
            }
            Self::Jwt { signature } => ensure!(
                !signature.is_empty() && signature.len() <= 128,
                "JWT requires a bounded named signature"
            ),
            Self::Duration { formats } => {
                ensure!(
                    formats.len() == 1,
                    "duration requires exactly one unambiguous unit format"
                );
                let definition = FieldContract::Duration {
                    unit: formats[0],
                    anchor: TimeAnchor::Observation,
                }
                .registered_definition(true)
                .expect("duration has a registered implementation");
                traffic_extensions::policies().prepare_definition(&definition)?;
            }
            Self::Unordered => {
                traffic_extensions::policies().prepare("unordered", &traffic_value::Value::Null)?;
            }
        }
        Ok(())
    }

    /// Source alone chooses the first declared matching format. Target cannot
    /// switch branches when another format would make a mismatch disappear.
    pub(crate) fn select_contract(&self, source: &Value) -> Result<FieldContract> {
        self.select_contract_with_clock(source, None)
    }

    pub(crate) fn select_contract_with_clock(
        &self,
        source: &Value,
        source_clock: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<FieldContract> {
        if matches!(self, Self::Policy(_)) {
            let value = serde_json::from_value(source.clone())?;
            return self.select_value_contract(&value, source_clock);
        }
        self.select_strict_contract(source, source_clock)
            .map(|contract| {
                if self.is_identity()
                    && !source.is_null()
                    && !matches!(contract, FieldContract::Identity { .. })
                {
                    FieldContract::IdentityAnchor
                } else {
                    contract
                }
            })
            .or_else(|error| {
                if source.is_array() || source.is_object() {
                    return Err(error);
                }
                // Source-only delivery has no differing Target output to explain.
                // Unknown scalar formats remain exact and are never translated.
                Ok(if self.is_identity() && !source.is_null() {
                    FieldContract::IdentityAnchor
                } else {
                    FieldContract::Exact
                })
            })
    }

    fn select_value_contract(
        &self,
        source: &traffic_value::Value,
        source_clock: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<FieldContract> {
        let Self::Policy(definition) = self else {
            return self.select_contract_with_clock(&serde_json::to_value(source)?, source_clock);
        };
        let prepared = traffic_extensions::policies().prepare_definition(definition)?;
        let facts = serde_json::from_value(serde_json::json!({
            "clocks":{"observation":{"source":source_clock,"target":null}}
        }))?;
        Ok(if prepared.applies(source, &facts)? {
            FieldContract::Policy(definition.clone())
        } else {
            FieldContract::Exact
        })
    }

    fn select_strict_contract(
        &self,
        source: &Value,
        source_clock: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<FieldContract> {
        // Null is a complete scalar value, distinct from a missing field. It
        // creates neither a timestamp observation nor an identity mapping.
        if source.is_null() && !matches!(self, Self::Unordered) {
            return Ok(FieldContract::Exact);
        }
        match self {
            Self::Policy(_) => {
                unreachable!("registered policies select their own Source applicability")
            }
            Self::Time { formats } => {
                let mut choices = formats
                    .iter()
                    .filter_map(|format| {
                        let contract = format.contract();
                        crate::value_contract::json::parse_time_value(
                            source,
                            &contract.time().expect("time contract"),
                        )
                        .ok()
                        .map(|instant| (instant, contract))
                    })
                    .collect::<Vec<_>>();
                ensure!(
                    !choices.is_empty(),
                    "Source value matches no declared time format"
                );
                if !source.is_number() || choices.len() == 1 {
                    return Ok(choices.remove(0).1);
                }
                // Numeric epoch encodings overlap syntactically. Infer units
                // only from immutable Source and its independent request clock.
                let Some(clock) = source_clock else {
                    return Ok(FieldContract::Exact);
                };
                let anchor = crate::value_contract::time::date_nanos(clock);
                choices.sort_by_key(|(instant, _)| instant.abs_diff(anchor));
                let best = &choices[0];
                if choices.iter().skip(1).any(|other| {
                    other.0.abs_diff(anchor) == best.0.abs_diff(anchor) && other.1 != best.1
                }) {
                    return Ok(FieldContract::Exact);
                }
                Ok(choices.remove(0).1)
            }
            Self::Identity { formats } => formats
                .iter()
                .find_map(|format| {
                    crate::value_contract::json::identity_token(
                        source,
                        &format.prefix,
                        format.format,
                        "",
                    )
                    .ok()
                    .map(|_| FieldContract::Identity {
                        prefix: format.prefix.clone(),
                        format: format.format,
                    })
                })
                .context("Source value matches no declared identity format"),
            Self::Url { .. } | Self::Jwt { .. } | Self::Template { .. } => {
                anyhow::bail!("protocol leaves use the prepared verifier")
            }
            Self::Duration { formats } => {
                ensure!(
                    !source.is_object() && !source.is_array(),
                    "duration requires a scalar"
                );
                let unit = *formats
                    .first()
                    .context("duration requires exactly one unit")?;
                Ok(FieldContract::Duration {
                    unit,
                    anchor: TimeAnchor::Observation,
                })
            }
            Self::Unordered => {
                ensure!(source.is_array(), "unordered requires an array");
                Ok(FieldContract::Unordered)
            }
        }
    }
}

impl JsonPolicy {
    pub fn compile(&self) -> Result<CompiledJsonPolicy> {
        self.compile_with_signatures(&BTreeMap::new())
    }

    pub(crate) fn compile_with_signatures(
        &self,
        signatures: &BTreeMap<String, super::SignatureDefinition>,
    ) -> Result<CompiledJsonPolicy> {
        self.compile_with_settings(signatures, &super::TimePolicy::default())
    }

    pub(crate) fn compile_with_settings(
        &self,
        signatures: &BTreeMap<String, super::SignatureDefinition>,
        time: &super::TimePolicy,
    ) -> Result<CompiledJsonPolicy> {
        time.offset()?;
        ensure!(
            self.fields.len() <= 4096,
            "json.fields accepts at most 4096 fields"
        );
        for (pointer, field) in &self.fields {
            super::validate_pointer(pointer, true)?;
            field
                .validate()
                .with_context(|| format!("invalid global JSON field {pointer:?}"))?;
        }
        let paths = self.fields.keys().collect::<Vec<_>>();
        for (index, left) in paths.iter().enumerate() {
            for right in paths.iter().skip(index + 1) {
                ensure!(
                    !overlaps(left, right),
                    "global JSON selectors {left:?} and {right:?} overlap"
                );
            }
        }
        Ok(CompiledJsonPolicy {
            fields: self.fields.clone(),
            time: time.clone(),
            fingerprint: super::digest("traffic-policy/global-json/v2", &(self, signatures, time))?,
            signatures: super::signatures::SignatureRegistry::new(
                signatures,
                &self
                    .fields
                    .values()
                    .filter_map(|field| match field {
                        GlobalField::Jwt { signature } => Some(signature.clone()),
                        _ => None,
                    })
                    .collect(),
            )?,
        })
    }
}

fn overlaps(left: &str, right: &str) -> bool {
    let left = left.split('/').collect::<Vec<_>>();
    let right = right.split('/').collect::<Vec<_>>();
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| *a == b || *a == "*" || b == "*")
}

impl CompiledJsonPolicy {
    #[cfg(test)]
    pub(crate) fn fields(&self, source: &Value) -> Result<Vec<(String, FieldContract)>> {
        self.fields_with_clocks(source, crate::value_contract::json::AnchorClocks::default())
    }

    pub(crate) fn identity_fields(&self, source: &Value) -> Result<Vec<(String, FieldContract)>> {
        Ok(self
            .select_authored_fields(source, None, true, None)?
            .into_iter()
            .map(|field| (field.pointer, field.contract))
            .collect())
    }

    pub(crate) fn fields_with_clocks(
        &self,
        source: &Value,
        clocks: crate::value_contract::json::AnchorClocks,
    ) -> Result<Vec<(String, FieldContract)>> {
        Ok(self
            .selected_fields_with_clocks(source, clocks)?
            .into_iter()
            .map(|field| (field.pointer, field.contract))
            .collect())
    }

    /// Standard textual time recognition permits comparison only. Delivery
    /// translation continues to require an authored field declaration.
    pub(crate) fn delivery_fields_with_clocks(
        &self,
        source: &Value,
        clocks: crate::value_contract::json::AnchorClocks,
    ) -> Result<Vec<(String, FieldContract)>> {
        Ok(self
            .selected_delivery_fields_with_clocks(source, clocks)?
            .into_iter()
            .map(|field| (field.pointer, field.contract))
            .collect())
    }

    pub(crate) fn selected_delivery_fields_with_clocks(
        &self,
        source: &Value,
        clocks: crate::value_contract::json::AnchorClocks,
    ) -> Result<Vec<SelectedGlobalField>> {
        self.select_authored_fields(source, clocks.observation().source, false, None)
    }

    pub(crate) fn comparison_fields(
        &self,
        source: &Value,
        _target: &Value,
        clocks: crate::value_contract::json::AnchorClocks,
    ) -> Result<Vec<(String, FieldContract)>> {
        // Equality is checked only after actual array-element pairing. A same
        // index Target hint would be unsafe under an unordered ancestor.
        self.fields_with_clocks(source, clocks)
    }

    pub(crate) fn selected_fields_with_clocks(
        &self,
        source: &Value,
        clocks: crate::value_contract::json::AnchorClocks,
    ) -> Result<Vec<SelectedGlobalField>> {
        self.select_fields(source, clocks, None)
    }

    pub(crate) fn selected_value_fields_with_clocks(
        &self,
        source: &traffic_value::Value,
        clocks: crate::value_contract::json::AnchorClocks,
    ) -> Result<Vec<SelectedGlobalField>> {
        self.select_fields(&serde_json::to_value(source)?, clocks, Some(source))
    }

    fn select_fields(
        &self,
        source: &Value,
        clocks: crate::value_contract::json::AnchorClocks,
        values: Option<&traffic_value::Value>,
    ) -> Result<Vec<SelectedGlobalField>> {
        let authored =
            self.select_authored_fields(source, clocks.observation().source, false, values)?;
        let mut selected = authored
            .into_iter()
            .map(|field| (field.pointer.clone(), field))
            .collect::<BTreeMap<_, _>>();
        let mut protocol_owned = std::collections::BTreeSet::new();
        for (pattern, field) in &self.fields {
            if matches!(
                field,
                GlobalField::Url { .. } | GlobalField::Template { .. } | GlobalField::Jwt { .. }
            ) {
                protocol_owned.extend(crate::value_contract::delivery::select(pattern, source)?);
            }
        }
        for (pointer, mut contract) in
            crate::value_contract::time::automatic::fields(source, &self.time)?
        {
            if protocol_owned.contains(&pointer) {
                continue;
            }
            if let Some(authored) = selected.get(&pointer) {
                let numeric_only = matches!(&self.fields[&authored.pattern], GlobalField::Time { formats } if formats.iter().all(|format| matches!(format.format, TimestampFormat::UnixSeconds | TimestampFormat::UnixMilliseconds | TimestampFormat::UnixMicroseconds)));
                if !numeric_only {
                    continue;
                }
            }
            scope_time(&pointer, &mut contract)?;
            selected.insert(
                pointer.clone(),
                SelectedGlobalField {
                    pattern: crate::value_contract::time::automatic::pointer_pattern(
                        source, &pointer,
                    ),
                    pointer,
                    contract,
                    rule_id: crate::value_contract::time::automatic::RULE_ID,
                },
            );
        }
        Ok(selected.into_values().collect())
    }

    fn select_authored_fields(
        &self,
        source: &Value,
        source_clock: Option<chrono::DateTime<chrono::Utc>>,
        identity_only: bool,
        values: Option<&traffic_value::Value>,
    ) -> Result<Vec<SelectedGlobalField>> {
        let mut fields = Vec::new();
        for (pattern, field) in &self.fields {
            if matches!(
                field,
                GlobalField::Url { .. } | GlobalField::Template { .. }
            ) {
                continue;
            }
            if matches!(field, GlobalField::Jwt { .. }) {
                if identity_only {
                    for pointer in crate::value_contract::delivery::select(pattern, source)? {
                        let value = source.pointer(&pointer).context("JWT field disappeared")?;
                        if crate::value_contract::global_protocol::is_jwt(value) {
                            fields.push(SelectedGlobalField {
                                pattern: pattern.clone(),
                                pointer,
                                contract: FieldContract::Identity {
                                    prefix: String::new(),
                                    format: IdentityFormat::Jwt,
                                },
                                rule_id: GLOBAL_JSON_ID,
                            });
                        } else if !value.is_null() && !value.is_array() && !value.is_object() {
                            fields.push(SelectedGlobalField {
                                pattern: pattern.clone(),
                                pointer,
                                contract: FieldContract::IdentityAnchor,
                                rule_id: GLOBAL_JSON_ID,
                            });
                        }
                    }
                }
                continue;
            }
            if identity_only && !field.is_identity() {
                continue;
            }
            for pointer in crate::value_contract::delivery::select(pattern, source)? {
                let value = source
                    .pointer(&pointer)
                    .context("selected Source field disappeared")?;
                let selected = if let Some(values) = values {
                    let Some(value) = values.pointer(&pointer) else {
                        continue;
                    };
                    field.select_value_contract(value, source_clock)
                } else {
                    field.select_contract_with_clock(value, source_clock)
                };
                let mut contract =
                    selected.with_context(|| format!("global JSON field {pointer:?}"))?;
                if identity_only
                    && !matches!(
                        contract,
                        FieldContract::Identity { .. } | FieldContract::IdentityAnchor
                    )
                {
                    continue;
                }
                scope_time(&pointer, &mut contract)?;
                fields.push(SelectedGlobalField {
                    pattern: pattern.clone(),
                    pointer,
                    contract,
                    rule_id: GLOBAL_JSON_ID,
                });
            }
        }
        Ok(fields)
    }
}

fn scope_time(pointer: &str, contract: &mut FieldContract) -> Result<()> {
    if let FieldContract::Time { clock_group, .. } = contract {
        let digest = super::digest("traffic-policy/global-json-clock/v1", &pointer)?;
        *clock_group = Some(format!("schema.{}", &digest[7..39]));
    }
    Ok(())
}

pub use traffic_contract::rule::is_schema_clock_group;

#[cfg(test)]
mod tests;
