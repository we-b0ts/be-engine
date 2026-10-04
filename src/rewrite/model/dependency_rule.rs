//! Persisted dependency-rule selectors and pending plan identity.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(in crate::rewrite) enum RewriteDependencyRuleSpec {
    RedisCrossCase {
        rule_id: String,
    },
    RedisTimeShift {
        selector: crate::RedisTimeShiftSelector,
    },
    HttpHeaderTimestamp {
        selector: crate::HttpHeaderTimestampSelector,
    },
    HttpUnordered {
        selector: crate::HttpUnorderedSelector,
    },
    RedisUnordered {
        selector: crate::RedisUnorderedSelector,
    },
    HttpCrossCase {
        selector: crate::HttpCrossCaseSelector,
    },
    MysqlSqlTime {
        selector: crate::MysqlTimeSelector,
    },
    Mysql {
        selector: crate::MysqlBackgroundSelector,
    },
    Http {
        authority: String,
        method: String,
        path_prefix: String,
    },
    Memcached {
        breeze_resource: String,
        command: String,
        key_start: u64,
        key_end: u64,
        key_separator: String,
        key_suffix: String,
        initial_load_timeout_ms: u64,
    },
    MemcachedProtobufTimestamp {
        rule_id: String,
        port: u16,
        key_prefix: String,
        key_suffix: String,
        field_number: u32,
    },
    Motan {
        group: String,
        interface_name: String,
        method_name: String,
    },
    RedisZcount {
        ports: Vec<u16>,
        key_prefix: String,
        key_suffix: String,
    },
    RedisGet {
        ports: Vec<u16>,
        keys: Vec<String>,
        initial_load_timeout_ms: u64,
    },
    RedisScard {
        ports: Vec<u16>,
        keys: Vec<String>,
        initial_load_timeout_ms: u64,
    },
    RedisHgetall {
        ports: Vec<u16>,
        keys: Vec<String>,
        initial_load_timeout_ms: u64,
    },
    RedisHscan {
        ports: Vec<u16>,
        keys: Vec<String>,
        key_patterns: Vec<RedisKeyPatternConfig>,
    },
    RedisHashRead {
        command: String,
        ports: Vec<u16>,
        keys: Vec<String>,
        key_patterns: Vec<RedisKeyPatternConfig>,
        fields: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::rewrite) struct RewriteDependencyRulePlanRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_fingerprint: Option<String>,
    pub id: String,
    pub issue_id: String,
    pub evidence_id: String,
    pub name: String,
    pub source_evidence: String,
    pub spec: RewriteDependencyRuleSpec,
    #[serde(default)]
    pub reused_existing: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_name: Option<String>,
}
