//! Closed API positions: algorithms and keys belong to named root profiles.
use super::*;
use crate::TimestampFormat;
use crate::native::{NonceFormat, ResponseNonceClaim};
use serde::{Deserialize, Serialize};

pub fn default_name() -> String {
    "default".into()
}
pub fn expiry_format() -> TimestampFormat {
    TimestampFormat::Rfc3339
}
pub fn default_expiry_format(format: &TimestampFormat) -> bool {
    *format == expiry_format()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    #[serde(default)]
    pub request: Option<Request>,
    #[serde(default)]
    pub response: Option<Response>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default, deserialize_with = "crate::strict_map::unique_map")]
    pub headers: BTreeMap<String, Header>,
    #[serde(default, deserialize_with = "crate::strict_map::unique_map")]
    pub query: BTreeMap<String, Reference>,
    #[serde(
        default,
        deserialize_with = "crate::strict_map::unique_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub socketio_connect: BTreeMap<String, ConnectFields>,
    #[serde(default)]
    pub body: Option<Body>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ConnectFields(
    #[serde(deserialize_with = "crate::strict_map::unique_map")] pub BTreeMap<String, Reference>,
);

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    #[serde(default, deserialize_with = "crate::strict_map::unique_map")]
    pub json: BTreeMap<String, JwtResponse>,
    #[serde(default, deserialize_with = "crate::strict_map::unique_map")]
    pub headers: BTreeMap<String, JwtResponse>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Reference {
    Name(String),
    Detailed {
        #[serde(default = "default_name")]
        signature: String,
        #[serde(default)]
        proof: Option<Proof>,
    },
}
impl Reference {
    pub fn parts(&self) -> (&str, Option<&Proof>) {
        match self {
            Self::Name(name) => (name, None),
            Self::Detailed { signature, proof } => (signature, proof.as_ref()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    #[serde(default = "default_name")]
    pub signature: String,
    #[serde(default)]
    pub scheme: HeaderScheme,
    #[serde(default)]
    pub proof: Option<Proof>,
}
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderScheme {
    #[default]
    Raw,
    Bearer,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    #[serde(default = "default_name")]
    pub signature: String,
    #[serde(deserialize_with = "crate::strict_map::unique_map")]
    pub fields: BTreeMap<String, String>,
    pub timestamp_pointer: String,
    pub signature_pointer: String,
    pub secret_parameter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JwtResponse {
    #[serde(default = "default_name")]
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nonces: Vec<Nonce>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(
        default = "expiry_format",
        skip_serializing_if = "default_expiry_format"
    )]
    pub expires_at_format: TimestampFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}
impl JwtResponse {
    pub fn new(signature: String) -> Self {
        Self {
            signature,
            query: None,
            nonces: vec![],
            expires_at: None,
            expires_at_format: expiry_format(),
            issued_at: None,
            ttl: None,
            proof: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Nonce {
    pub pointer: String,
    pub format: NonceFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub echo_query_param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}
impl Nonce {
    pub fn contract(&self) -> ResponseNonceClaim {
        ResponseNonceClaim {
            pointer: self.pointer.clone(),
            format: self.format.clone(),
            echo_query_param: self.echo_query_param.clone(),
        }
    }
}
