mod config;
mod feedback;
pub(crate) use feedback::replace_request_rule_section;
pub use feedback::{
    RedisTimeShiftFeedback, RedisTimeShiftPlan, RedisTimeShiftReport, plan_redis_time_shift,
};
mod initialization;
mod matcher;
mod pattern;
mod protobuf;
mod report;
mod response;
mod sql_template;
mod value;

#[cfg(test)]
mod tests;

pub use config::{ReplayPolicyValidationReport, validate_replay_policy};
pub(in crate::replay) use config::{fingerprint, load_replay_policy};
pub use feedback::{
    ComparisonResponseRuleFeedback, MemcachedTimestampRuleFeedback, MemcachedTimestampRulePlan,
    MemcachedTimestampRuleReport, MysqlTimeRuleFeedback, MysqlTimeRulePlan, MysqlTimeRuleReport,
    MysqlTimeSelector, ProfileTargetMissingFeedback, ProfileTargetMissingPlan,
    ProfileTargetMissingReport, ResponseBodyRuleEvidence, ResponseBodyRuleEvidenceKind,
    ResponseBodyRuleFeedback, ResponseBodyRulePlan, ResponseBodyRuleReport,
    ResponseBodyRuleVerificationOutcome, ResponseRuleFeedback, ResponseRulePlan,
    ResponseRuleReport, plan_comparison_response_rule, plan_memcached_timestamp_rule,
    plan_mysql_time_rule, plan_profile_target_missing, plan_response_body_rule, plan_response_rule,
};
pub(crate) use initialization::render_validated_replay_policy;
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
    ComparisonSourceMatch, ComparisonVerificationPolicy, DocxTimestampRule,
    Hessian2JoinedStringPath, Hessian2UnorderedPath, Hessian2ValuePath, ProtobufFieldPath,
    ProtobufJoinedStringFieldType, ProtobufJoinedStringPath, ProtobufRepeatedElementType,
    ProtobufUnorderedPath, ResponseBodyCodec, ResponseBodyJoinedStringPath,
    ResponseBodyUnorderedPath, ResponseDurationUnit, ResponseField, ResponseRuleKind,
    ResponseTimeRule, ResponseTimestampFormat,
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
        .filter(|r| r.replay_scope == config::ReplayScope::RecordingRun)
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

pub use feedback::{
    HttpCrossCaseFeedback, HttpCrossCasePlan, HttpCrossCaseReport, plan_http_cross_case,
};

mod http_json;
pub(in crate::replay) use response::{response_pointer_matches, validate_json_pointer};

pub use feedback::{
    HttpUnorderedFeedback, HttpUnorderedPlan, HttpUnorderedReport, plan_http_unordered,
};

mod redis_value;

pub use feedback::{
    RedisUnorderedFeedback, RedisUnorderedPlan, RedisUnorderedReport, plan_redis_unordered,
};
