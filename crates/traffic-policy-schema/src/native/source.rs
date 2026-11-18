//! Acquisition, origin classification and finite sharing have separate effects.
use std::{collections::BTreeMap, net::SocketAddr};

use serde::{Deserialize, Serialize};

use super::{Literal, NativeKeySelector, Proven};
use crate::{Resource, SourceScalar};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureHttpEffect {
    pub source_revision: String,
    pub case_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureResponseEffect {
    pub authorities: Vec<String>,
    pub methods: Vec<String>,
    pub path: CapturePath,
    pub status_codes: Vec<u16>,
    pub content_types: Vec<String>,
    pub contract: CaptureResponseContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapturePath {
    Exact { value: String },
    Pattern { value: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureResponseContract {
    Policy(traffic_policy::PolicyDefinition),
    Urls {
        pointers: Vec<Proven<String>>,
    },
    Kubeconfig {
        kubectl_binary: String,
        proxy_listen: SocketAddr,
    },
    Documents {
        rules: Vec<traffic_response_rewrite::DocumentRule>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessOwnedEffect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_name: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_revision: String,
    pub selector: ProcessSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Proven<ApiOrigin>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcessSelector {
    RedisPubsub(RedisPubsubSelector),
    Mysql {
        selector: MysqlProcessSelector,
        #[serde(default)]
        include_transaction_boundaries: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        transaction_members: Vec<Proven<MysqlProcessSelector>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity_value_index: Option<usize>,
    },
    Http {
        authorities: Vec<String>,
        methods: Vec<String>,
        path_prefixes: Vec<String>,
    },
    Memcached {
        breeze_identity: String,
        operation: String,
        key_start: u64,
        key_end: u64,
        key_separator: String,
        key_suffix: String,
        initial_load_timeout_ms: u64,
    },
    Redis {
        ports: Vec<u16>,
        operation: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        keys: Vec<NativeKeySelector>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        key_templates: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        key_sequence: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        arguments: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        script: Option<Proven<OriginScript>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_load_timeout_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fields: Vec<String>,
        #[serde(
            default,
            deserialize_with = "super::super::strict_map::unique_map",
            skip_serializing_if = "std::collections::BTreeMap::is_empty"
        )]
        when_message: std::collections::BTreeMap<String, RedisPublishPredicate>,
    },
    Motan {
        group: String,
        interface: String,
        method: String,
    },
}

/// A condition on one concrete JSON pointer in the outgoing PUBLISH payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum RedisPublishPredicate {
    Equals { equals: serde_json::Value },
    Prefix { prefix: String },
}

/// Ownership of received native inputs, independent of their external publisher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisPubsubSelector {
    pub resource: Resource,
    pub channel: String,
    pub kind: RedisPubsubKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedisPubsubKind {
    Message,
    Pmessage,
    Smessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MysqlProcessSelector {
    pub resource: Resource,
    pub sql: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub table_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_series: Option<traffic_protocol_mysql::table_selector::MysqlTableSeries>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiOrigin {
    pub api: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::strict_map::unique_map")]
    pub request_body: BTreeMap<String, SourceScalar>,
    #[serde(deserialize_with = "crate::strict_map::unique_map")]
    pub capture: BTreeMap<String, Proven<OriginCapture>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginCapture {
    pub resource: Resource,
    pub operation: OriginOperation,
    pub tables: Vec<String>,
    pub table_patterns: Vec<String>,
    #[serde(deserialize_with = "crate::strict_map::unique_map")]
    pub row_match: BTreeMap<String, Literal>,
    pub column: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OriginOperation {
    #[serde(rename = "INSERT")]
    Insert,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginScript {
    pub sha1: String,
    pub keys: Vec<NativeKeySelector>,
    pub argv_count: usize,
    pub identity_argv_index: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum FiniteSharingEffect {
    Http,
    Redis {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hash_field: Option<String>,
    },
}
