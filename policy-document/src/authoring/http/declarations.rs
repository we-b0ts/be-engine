//! Compact HTTP carrier positions; native effects retain execution ownership.
use super::*;
use serde::{Deserialize, Deserializer, Serialize};
use traffic_protocol_http::request_sigv4::SigV4RequestRule;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpDocument {
    #[serde(default, deserialize_with = "optional_headers")]
    pub headers: Option<BTreeMap<String, crate::GlobalField>>,
    #[serde(default)]
    pub request_metadata: Vec<traffic_protocol_http::request_metadata::RequestMetadataRule>,
    #[serde(default)]
    pub requests: Vec<RequestDeclaration>,
    #[serde(default)]
    pub response_rewrite: Vec<ResponseRewrite>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RequestDeclaration {
    PathIdentity(PathRequest),
    SigV4(SigV4RequestRule),
}

pub fn optional_headers<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, crate::GlobalField>>, D::Error> {
    crate::strict_map::unique_map(deserializer).map(Some)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRequest {
    pub host: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    pub path_identity: PathIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathIdentity {
    pub segment: usize,
    pub template: String,
    #[serde(deserialize_with = "crate::strict_map::unique_map")]
    pub fields: BTreeMap<String, Annotated<PathField>>,
    pub references: Vec<Annotated<ResourceReference>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseRewrite {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub host: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub json_urls: Vec<Annotated<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub documents: Vec<traffic_response_rewrite::DocumentRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<traffic_policy::PolicyDefinition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status_codes: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub host: String,
    pub method: String,
    pub path: String,
    pub api: Option<String>,
    pub path_identity: Option<PathIdentity>,
    pub response: Option<Capture>,
    pub proof: Option<Proof>,
}

#[derive(Debug, Clone)]
pub struct Capture {
    pub name: Option<String>,
    pub capture_urls: Vec<Annotated<String>>,
    pub documents: Vec<traffic_response_rewrite::DocumentRule>,
    pub policy: Option<traffic_policy::PolicyDefinition>,
    pub status_codes: Vec<u16>,
    pub content_types: Vec<String>,
}

impl From<PathRequest> for Request {
    fn from(request: PathRequest) -> Self {
        Self {
            host: request.host,
            method: request.method,
            path: request.path,
            api: request.api,
            path_identity: Some(request.path_identity),
            response: None,
            proof: request.proof,
        }
    }
}

impl From<ResponseRewrite> for Request {
    fn from(rewrite: ResponseRewrite) -> Self {
        Self {
            host: rewrite.host,
            method: rewrite.method,
            path: rewrite.path,
            api: None,
            path_identity: None,
            response: Some(Capture {
                name: rewrite.name,
                capture_urls: rewrite.json_urls,
                documents: rewrite.documents,
                policy: rewrite.policy,
                status_codes: rewrite.status_codes,
                content_types: rewrite.content_types,
            }),
            proof: rewrite.proof,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Annotated<T> {
    Proven {
        contract: T,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof: Option<Proof>,
    },
    Bare(T),
}

impl<T> Annotated<T> {
    pub fn parts(&self) -> (&T, Option<&Proof>) {
        match self {
            Self::Proven { contract, proof } => (contract, proof.as_ref()),
            Self::Bare(contract) => (contract, None),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceReference {
    Name(String),
    Physical(Resource),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum PathField {
    Exact(Exact),
    Hex {
        hex: usize,
    },
    Timestamp {
        timestamp: String,
        #[serde(default = "utc", skip_serializing_if = "is_utc")]
        timezone: String,
        #[serde(default, skip_serializing_if = "is_preserved_time")]
        mode: PathTimestampMode,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exact {
    Exact,
}

pub fn utc() -> String {
    "UTC".into()
}

pub fn is_utc(timezone: &str) -> bool {
    timezone == "UTC"
}

pub fn is_preserved_time(mode: &PathTimestampMode) -> bool {
    *mode == PathTimestampMode::PreserveOrRequestWindow
}
