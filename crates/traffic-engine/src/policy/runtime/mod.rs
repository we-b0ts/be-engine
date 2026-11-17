pub(crate) mod case_condition;
mod config;
pub(crate) mod native_crypto_key;
mod service;
pub use case_condition::{CaseCondition, JsonCondition};
pub(crate) mod dynamic_values;
pub(crate) mod request_contract;
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
mod initialization;
pub(crate) mod native_projection;
pub use native_projection::{SourceInputCase, validate_source_inputs};
mod matcher;

mod pattern;
mod report;
mod response;
pub(crate) mod response_headers;
pub use response_headers::ResponseHeaderDateRule;
mod sql_template;
mod value;

#[cfg(any(test, feature = "test-support"))]
pub mod test_fixture;
#[cfg(test)]
mod tests;

pub(crate) use config::{LoadedReplayPolicy, fingerprint, load_replay_policy};
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
pub(crate) use pattern::uri_path;
pub(crate) use response::response_locations_overlap;
pub use response::{
    DocxTimestampRule, Hessian2JoinedStringPath, Hessian2UnorderedPath, Hessian2ValuePath,
    ProtobufFieldPath, ProtobufJoinedStringFieldType, ProtobufJoinedStringPath,
    ProtobufRepeatedElementType, ProtobufUnorderedPath, ResponseBodyCodec,
    ResponseBodyJoinedStringPath, ResponseBodyUnorderedPath, ResponseDurationUnit, ResponseField,
    ResponseRuleKind, ResponseTimeRule, ResponseTimestampFormat, ResponseTimestampMode,
};

#[allow(dead_code)]
/// Read only explicit cross-case selectors before dependency preload.
pub(crate) fn http_cross_case_rules(
    path: &std::path::Path,
) -> anyhow::Result<Vec<(String, crate::HttpCrossCaseSelector)>> {
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
                crate::HttpCrossCaseSelector {
                    host: r.target.host,
                    port: r.target.port,
                    method: http.method,
                    path: http.path,
                },
            )
        })
        .collect())
}

#[allow(dead_code)]
/// Redis sharing retains exact physical read identity and finite inventory.
pub(crate) fn redis_cross_case_rules(
    path: &std::path::Path,
) -> anyhow::Result<
    Vec<(
        String,
        traffic_protocol_redis::bindings::RedisSharedReadSelector,
    )>,
> {
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
            let redis_value::RedisSelector::SharedRead(read) =
                rule.redis.expect("validated Redis scope")
            else {
                unreachable!("validated Redis scope uses shared read")
            };
            Some((
                rule.id,
                traffic_protocol_redis::bindings::RedisSharedReadSelector {
                    host: rule.target.host,
                    port: rule.target.port,
                    read,
                },
            ))
        })
        .collect())
}

pub use feedback::{
    HttpCrossCaseFeedback, HttpCrossCasePlan, HttpCrossCaseReport, plan_http_cross_case,
};

mod redis_value;

pub use feedback::{DependencyRequestRuleFeedback, plan_dependency_request_rule};

pub use response::{ResponseJwtAlgorithm, ResponseJwtKeySource, ResponseJwtRule};

pub use feedback::{ResponseJwtRuleFeedback, plan_response_jwt_rule};

pub(crate) use response::ResponseBodyRuleMatch;

pub use matcher::ReplayPolicyRuntime;

pub use request_contract::RequestContracts;

pub(crate) use native_projection::validate_finite_sharing as validate_native_finite_sharing;
pub(crate) use native_projection::{compiled_input_rules, validate_native_adapter};
pub(crate) use request_contract::discover as discover_dependency_request_candidates;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use test_fixture::redis_time::RedisTimeShiftFeedback;
#[cfg(test)]
pub(crate) use test_fixture::write_policy as write_policy_fixture;

#[cfg(test)]
pub(crate) use test_fixture::redis_time::RedisTimeShiftSelector;
