//! Authoring section data independent of runtime preparation and key snapshots.
use crate::{GlobalField, POLICY_FORMAT};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonPolicy {
    #[serde(deserialize_with = "traffic_policy_schema::strict_map::unique_map")]
    pub fields: BTreeMap<String, GlobalField>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MysqlPolicy {
    #[serde(
        default,
        deserialize_with = "traffic_policy_schema::strict_map::unique_map"
    )]
    pub tables: BTreeMap<String, GlobalMysqlTable>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalMysqlTable {
    pub pattern: String,
    #[serde(deserialize_with = "traffic_policy_schema::strict_map::unique_map")]
    pub fields: BTreeMap<String, GlobalField>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisPolicy {
    #[serde(
        default,
        deserialize_with = "traffic_policy_schema::strict_map::unique_map"
    )]
    pub keys: BTreeMap<String, GlobalField>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpPolicy {
    #[serde(
        default,
        deserialize_with = "traffic_policy_schema::strict_map::unique_map"
    )]
    pub headers: BTreeMap<String, GlobalField>,
}
impl HttpPolicy {
    pub fn compile(&self, context: &crate::AuthoringContext<'_>) -> anyhow::Result<Self> {
        use anyhow::ensure;
        let mut headers = BTreeMap::new();
        ensure!(
            self.headers.len() <= 4096,
            "http.headers exceeds 4096 entries"
        );
        for (name, field) in &self.headers {
            ensure!(
                name.len() <= 256 && !name.contains('*'),
                "HTTP header strategy requires a bounded exact header name"
            );
            let name = hyper::header::HeaderName::from_bytes(name.as_bytes())?
                .as_str()
                .to_owned();
            ensure!(
                !matches!(
                    name.as_str(),
                    "content-length"
                        | "transfer-encoding"
                        | "connection"
                        | "trailer"
                        | "content-encoding"
                        | "content-md5"
                        | "digest"
                        | "content-digest"
                        | "repr-digest"
                        | "signature"
                        | "signature-input"
                ),
                "HTTP framing and integrity headers cannot declare value formats"
            );
            field.validate_with_registry(context.compilation.policies)?;
            ensure!(
                matches!(
                    field,
                    GlobalField::Policy(_)
                        | GlobalField::Time { .. }
                        | GlobalField::Identity { .. }
                        | GlobalField::Duration { .. }
                ),
                "HTTP headers accept registered policies and time, identity or duration formats"
            );
            ensure!(
                headers.insert(name, field.clone()).is_none(),
                "HTTP header declarations repeat a case-insensitive name"
            );
        }
        Ok(Self { headers })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrafficPolicy {
    pub format: String,
    pub source_revision: Option<String>,
    pub time: crate::TimePolicy,
    pub json: Option<crate::JsonPolicy>,
    pub mysql: Option<crate::MysqlPolicy>,
    pub redis: Option<crate::RedisPolicy>,
    pub http: Option<crate::HttpPolicy>,
    pub async_api: Option<BTreeMap<String, crate::AsyncApiRules>>,
    pub signatures: BTreeMap<String, crate::SignatureDefinition>,
    pub resources: BTreeMap<String, crate::ResourceDeclaration>,
    pub rules: Vec<crate::PolicyRule>,
}

impl Default for TrafficPolicy {
    fn default() -> Self {
        Self {
            format: POLICY_FORMAT.into(),
            source_revision: None,
            time: Default::default(),
            json: None,
            mysql: None,
            redis: None,
            http: None,
            async_api: None,
            signatures: BTreeMap::new(),
            resources: BTreeMap::new(),
            rules: Vec::new(),
        }
    }
}
