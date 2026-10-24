pub(crate) mod case_condition;
mod config;
pub(crate) mod native_crypto_key;
pub use case_condition::{CaseCondition, JsonCondition};
mod evidence_policy;
pub(in crate::replay) mod request_contract;
pub(crate) use evidence_policy::ReplayEvidencePolicyFreshness;
pub(in crate::replay) mod dynamic_values;
pub use dynamic_values::{
    DynamicValueCapture, DynamicValueFormat, DynamicValueRule, DynamicValueTarget,
    DynamicValueType, PathSegmentCapture, PathSegmentField, RedisCaptureReference,
    RedisDerivedIdentity,
};
mod feedback;
pub(crate) use feedback::replace_request_rule_section;
pub use feedback::{
    DynamicValueMysqlTimeRule, DynamicValueRedisTimeRule, DynamicValueRuleFeedback,
    GeneratedValueRulePlan, GeneratedValueRuleReport, RedisJsonTimeValueSelector,
    ResponseHeaderDateRuleFeedback, plan_dynamic_value_mysql_time_rule,
    plan_dynamic_value_redis_time_rule, plan_dynamic_value_rule, plan_response_header_date_rule,
};
pub use feedback::{
    RedisCrossCaseFeedback, RedisCrossCasePlan, RedisCrossCaseReport, plan_redis_cross_case,
};
pub use feedback::{
    RedisTimeShiftFeedback, RedisTimeShiftPlan, RedisTimeShiftReport, plan_redis_time_shift,
};
mod initialization;
pub(crate) mod native_projection;
pub(crate) use native_projection::validate_finite_sharing;
pub(crate) use native_projection::{NativeSourceCase, validate_native_source_dependencies};
mod matcher;
pub(crate) use matcher::mysql_contract::{
    compare_values as compare_mysql_values, selected_value as mysql_contract_value,
    validate_selector as validate_mysql_value_selector, witness_matches as mysql_witness_matches,
};
pub(in crate::replay) use matcher::mysql_native::fields::{
    matches_field as mysql_field_matches, values as mysql_field_values,
};
pub(crate) use matcher::mysql_native::witness_matches as mysql_native_witness_matches;
mod pattern;
mod protobuf;
mod report;
mod response;
pub(in crate::replay) mod response_headers;
pub use response_headers::ResponseHeaderDateRule;
mod sql_template;
mod value;

#[cfg(test)]
pub(crate) mod test_fixture;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(in crate::replay) use config::ReplayPolicyDocument;
pub(in crate::replay) use config::{LoadedReplayPolicy, fingerprint, load_replay_policy};
pub use config::{ReplayPolicyValidationReport, validate_replay_policy};
pub use feedback::{
    MemcachedTimestampRuleFeedback, MemcachedTimestampRulePlan, MemcachedTimestampRuleReport,
    MysqlTimeRuleFeedback, MysqlTimeRulePlan, MysqlTimeRuleReport, MysqlTimeSelector,
    MysqlTimeValueSelector, ResponseBodyRuleEvidence, ResponseBodyRuleEvidenceKind,
    ResponseBodyRuleFeedback, ResponseBodyRulePlan, ResponseBodyRuleReport,
    ResponseBodyRuleVerificationOutcome, ResponseRuleFeedback, ResponseRulePlan,
    ResponseRuleReport, plan_memcached_timestamp_rule, plan_mysql_time_rule,
    plan_response_body_rule, plan_response_rule,
};
pub use initialization::{
    ReplayPolicyInitOptions, ReplayPolicyInitResult, initialize_replay_policy,
};
pub(in crate::replay) use matcher::{
    DependencyRuleDecision, HttpPolicyContext, MemcachedPolicyContext, MysqlPolicyContext,
    ReplayPolicyRuntime,
};
pub(in crate::replay) use pattern::uri_path;
pub(in crate::replay) use report::ReplayPolicyReport;
pub(crate) use response::response_locations_overlap;
pub(in crate::replay) use response::select_json_pointers;
pub use response::{
    DocxTimestampRule, Hessian2JoinedStringPath, Hessian2UnorderedPath, Hessian2ValuePath,
    ProtobufFieldPath, ProtobufJoinedStringFieldType, ProtobufJoinedStringPath,
    ProtobufRepeatedElementType, ProtobufUnorderedPath, ResponseBodyCodec,
    ResponseBodyJoinedStringPath, ResponseBodyUnorderedPath, ResponseDurationUnit, ResponseField,
    ResponseRuleKind, ResponseTimeRule, ResponseTimestampFormat, ResponseTimestampMode,
};

/// Read only explicit cross-case selectors before dependency preload.
pub(in crate::replay) fn http_cross_case_rules(
    path: &std::path::Path,
) -> anyhow::Result<Vec<(String, crate::replay::HttpCrossCaseSelector)>> {
    let loaded = load_replay_policy(path)?;
    Ok(loaded
        .document
        .dependency_rules
        .into_iter()
        .filter(|r| {
            r.replay_scope == config::ReplayScope::RecordingRun
                && r.protocol == config::DependencyProtocol::Http
        })
        .map(|r| {
            let http = r.http.expect("validated HTTP scope");
            (
                r.id,
                crate::replay::HttpCrossCaseSelector {
                    host: r.target.host.unwrap(),
                    port: r.target.port.unwrap(),
                    method: http.method,
                    path: http.path,
                },
            )
        })
        .collect())
}

/// Redis scope rules reuse the exact selector of an existing time-shift rule.
pub(in crate::replay) fn redis_cross_case_rules(
    path: &std::path::Path,
) -> anyhow::Result<Vec<(String, crate::replay::RedisTimeShiftSelector)>> {
    let loaded = load_replay_policy(path)?;
    Ok(loaded
        .document
        .dependency_rules
        .into_iter()
        .filter_map(|rule| {
            if rule.replay_scope != config::ReplayScope::RecordingRun
                || rule.protocol != config::DependencyProtocol::Redis
            {
                return None;
            }
            let redis_value::RedisSelector::TimeShift(read) =
                rule.redis.expect("validated Redis scope")
            else {
                unreachable!("validated Redis scope uses time-shift")
            };
            Some((
                rule.id,
                crate::replay::RedisTimeShiftSelector {
                    host: rule.target.host.expect("validated Redis host"),
                    port: rule.target.port.expect("validated Redis port"),
                    read,
                },
            ))
        })
        .collect())
}

pub use feedback::{
    HttpCrossCaseFeedback, HttpCrossCasePlan, HttpCrossCaseReport, plan_http_cross_case,
};

pub(in crate::replay) mod http_client_metadata;
mod http_headers;
mod http_json;
pub use http_headers::HttpHeaderTimestampSelector;
pub(in crate::replay) use response::{response_pointer_matches, validate_json_pointer};

pub use feedback::{
    HttpUnorderedFeedback, HttpUnorderedPlan, HttpUnorderedReport, plan_http_unordered,
};

mod redis_value;

pub use feedback::{
    RedisUnorderedFeedback, RedisUnorderedPlan, RedisUnorderedReport, plan_redis_unordered,
};

pub use feedback::{
    HttpHeaderTimestampFeedback, HttpHeaderTimestampPlan, HttpHeaderTimestampReport,
    plan_http_header_timestamp,
};

pub use feedback::{RedisLockFeedback, RedisLockPlan, RedisLockReport, plan_redis_lock};
pub use feedback::{
    RedisPublishFeedback, RedisPublishPlan, RedisPublishReport, plan_redis_publish,
};

pub use feedback::{DependencyRequestRuleFeedback, plan_dependency_request_rule};

pub use response::{ResponseJwtAlgorithm, ResponseJwtKeySource, ResponseJwtRule};

pub use feedback::{ResponseJwtRuleFeedback, plan_response_jwt_rule};

pub(in crate::replay) use response::ResponseBodyRuleMatch;

pub(crate) use matcher::mysql_native::{
    CopyProofs as MysqlTimeCopyProofs,
    compare_with_time_copies as compare_mysql_contracts_with_time_copies,
};
