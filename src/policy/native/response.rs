//! Assertion-only contracts and explicit structured-body field ownership.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Literal, NonceClaim, Proven, SignatureAlgorithm, StartupKey};
use crate::policy::{DurationUnit, Resource, TimestampFormat};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseJwtEffect {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pointer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<ResponseJwtLocation>,
    pub algorithm: SignatureAlgorithm,
    pub signing_key: ResponseSigningKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nonces: Vec<Proven<ResponseNonceClaim>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_query_param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(
        default = "default_expiry_format",
        skip_serializing_if = "is_default_expiry_format"
    )]
    pub expires_at_format: TimestampFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseJwtLocation {
    pub header: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseNonceClaim {
    pub pointer: String,
    pub format: super::NonceFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub echo_query_param: Option<String>,
}

impl From<NonceClaim> for ResponseNonceClaim {
    fn from(value: NonceClaim) -> Self {
        Self {
            pointer: value.pointer,
            format: value.format,
            echo_query_param: None,
        }
    }
}

fn default_expiry_format() -> TimestampFormat {
    TimestampFormat::Rfc3339
}
fn is_default_expiry_format(value: &TimestampFormat) -> bool {
    *value == default_expiry_format()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseSigningKey {
    Startup {
        source: StartupKey,
    },
    /// Recorded public keys are assertion oracles and cannot sign inbound requests.
    RecordedPublicKey {
        resource: Box<Resource>,
        sql: String,
        params: Vec<Literal>,
        column: String,
        json_pointer: String,
        kid_pointer: String,
        algorithm_pointer: String,
        kid: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderDateEffect {
    pub header: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    pub format: String,
    pub timezone: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedEffect {
    #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
    pub fields: BTreeMap<String, Proven<GeneratedResponse>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratedResponse {
    Uuid,
    UuidV4,
    Random {
        format: RandomEncoding,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        length: Option<usize>,
    },
    Template {
        template: String,
        #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
        fields: BTreeMap<String, Proven<TemplateToken>>,
    },
    EncryptedJson {
        envelope: CipherEnvelope,
        key: EncryptionKey,
        #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
        fields: BTreeMap<String, Proven<PlaintextContract>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateToken {
    pub format: RandomEncoding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
}

/// Cipher-only key resolution. JWT signing never consumes Source defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EncryptionKey {
    Startup {
        source: StartupKey,
    },
    StartupOrSourceDefault {
        source: StartupKey,
        fallback: SourceDefaultKey,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDefaultKey {
    pub path: String,
    pub file_sha256: String,
    /// Half-open byte range containing the literal value in frozen Source.
    pub byte_range: [u64; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RandomEncoding {
    Uuid,
    Hex,
    Base64,
    Base64url,
    Alphanumeric,
    Decimal,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipherEnvelope {
    Base64IvAesCbcPkcs7,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlaintextContract {
    Unordered,
    Time(super::NativeTime),
    Duration {
        unit: DurationUnit,
        anchor: crate::policy::TimeAnchor,
    },
    UuidV4,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyEffect {
    pub codec: BodyCodec,
    pub fields: Vec<Proven<BodyField>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyCodec {
    Json,
    Protobuf,
    Hessian2,
    Docx,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BodyField {
    Unordered {
        selector: BodySelector,
    },
    JoinedString {
        selector: BodySelector,
        separator: String,
    },
    Timestamp {
        part: String,
        element: String,
        format: TimestampFormat,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BodySelector {
    Json {
        pointer: String,
    },
    Protobuf {
        field_path: Vec<u32>,
        alias: String,
        element_type: ProtobufElement,
    },
    Hessian2 {
        value_path: Vec<String>,
        alias: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtobufElement {
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
    String,
}

impl From<ProtobufElement> for crate::policy::ProtobufType {
    fn from(value: ProtobufElement) -> Self {
        use crate::policy::ProtobufType as P;
        match value {
            ProtobufElement::String => P::String,
            ProtobufElement::Message => P::Message,
            ProtobufElement::Int32 => P::Int32,
            ProtobufElement::Int64 => P::Int64,
            ProtobufElement::Uint32 => P::Uint32,
            ProtobufElement::Uint64 => P::Uint64,
            ProtobufElement::Sint32 => P::Sint32,
            ProtobufElement::Sint64 => P::Sint64,
            ProtobufElement::Fixed32 => P::Fixed32,
            ProtobufElement::Fixed64 => P::Fixed64,
            ProtobufElement::Sfixed32 => P::Sfixed32,
            ProtobufElement::Sfixed64 => P::Sfixed64,
            ProtobufElement::Bool => P::Bool,
            ProtobufElement::Enum => P::Enum,
            ProtobufElement::Float => P::Float,
            ProtobufElement::Double => P::Double,
        }
    }
}

impl BodyEffect {
    /// Static capability and runtime decoding consume this same typed binding.
    pub(crate) fn value_codec(&self) -> anyhow::Result<Option<crate::policy::Codec>> {
        use crate::policy::{Codec, ProtobufCodec, ProtobufField};
        match self.codec {
            BodyCodec::Json => Ok(Some(Codec::Json)),
            BodyCodec::Protobuf => {
                let mut fields = BTreeMap::new();
                for value in &self.fields {
                    let selector = match &value.contract {
                        BodyField::Unordered { selector }
                        | BodyField::JoinedString { selector, .. } => selector,
                        _ => anyhow::bail!("Protobuf body requires a field selector"),
                    };
                    let BodySelector::Protobuf {
                        field_path,
                        alias,
                        element_type,
                    } = selector
                    else {
                        anyhow::bail!("Protobuf body requires a typed wire binding")
                    };
                    let field = ProtobufField {
                        field_path: field_path.clone(),
                        field_type: (*element_type).into(),
                        repeated: true,
                    };
                    anyhow::ensure!(
                        fields.insert(alias.clone(), field).is_none(),
                        "duplicate native Protobuf alias"
                    );
                }
                let codec = Codec::Protobuf(ProtobufCodec { fields });
                crate::policy::compiler::validate_codec(&codec)?;
                Ok(Some(codec))
            }
            BodyCodec::Hessian2 | BodyCodec::Docx => Ok(None),
        }
    }
}
