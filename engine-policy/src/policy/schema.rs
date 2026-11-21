//! Typed traffic-policy/v3 rules. Authoring defaults expand before compilation.
use std::collections::BTreeMap;

pub const POLICY_FORMAT: &str = "traffic-policy/v3";

#[derive(Debug, Clone, PartialEq)]
pub struct TrafficPolicy {
    pub format: String,
    pub source_revision: Option<String>,
    pub time: super::TimePolicy,
    pub json: Option<super::JsonPolicy>,
    pub mysql: Option<super::MysqlPolicy>,
    pub redis: Option<super::RedisPolicy>,
    pub http: Option<super::HttpPolicy>,
    pub async_api: Option<BTreeMap<String, super::AsyncApiRules>>,
    pub signatures: BTreeMap<String, super::SignatureDefinition>,
    pub resources: BTreeMap<String, super::ResourceDeclaration>,
    pub rules: Vec<super::PolicyRule>,
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

pub use traffic_policy_schema::value_binding::*;
