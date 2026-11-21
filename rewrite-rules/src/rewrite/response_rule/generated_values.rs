//! Generated identity and clock rule construction with frozen evidence checks.
use super::*;
use crate::{DynamicValueRuleFeedback, GeneratedValueRulePlan, ResponseHeaderDateRuleFeedback};

pub fn validate_companions(dynamic: bool, mysql: bool, redis: bool) -> Result<()> {
    ensure!(
        !mysql || dynamic,
        "a MySQL time companion requires a dynamic identity rule"
    );
    ensure!(
        !redis || dynamic,
        "a Redis time companion requires a dynamic identity rule"
    );
    ensure!(
        !(mysql && redis),
        "MySQL and Redis time companions cannot be combined"
    );
    Ok(())
}
pub fn build(
    target_root: &Path,
    state: &RewriteState,
    record: &RewriteRulePlanRecord,
) -> Result<GeneratedValueRulePlan> {
    GeneratedValueRulePlan::ensure_evidence_current(&record.generated_witnesses).context(
        "pending generated-value evidence is stale; recover the plan and run fresh Replay",
    )?;
    let plan = build_unfrozen(target_root, state, record)?;
    ensure!(
        plan.evidence_witnesses() == record.generated_witnesses,
        "generated value evidence changed after planning"
    );
    Ok(plan)
}

pub fn build_unfrozen(
    target_root: &Path,
    state: &RewriteState,
    record: &RewriteRulePlanRecord,
) -> Result<GeneratedValueRulePlan> {
    validate_companions(
        record.dynamic_value.is_some(),
        record.mysql_time.is_some(),
        record.redis_time.is_some(),
    )?;
    let policy_path = target_root.join(".traffic-e2e/verification.yaml");
    let evidence = {
        let evidence = resolve_e2e_response_rule_evidence(
            E2eRunContext {
                target_root: target_root.into(),
                case_source: state
                    .case_source
                    .clone()
                    .context("generated rule requires finalized recordings")?,
                run_key: None,
            },
            state
                .group_id
                .as_deref()
                .context("generated rule requires a prepared group")?,
        )?;
        if let Some(rule) = &record.dependency_request {
            return crate::plan_dependency_request_rule(crate::DependencyRequestRuleFeedback {
                policy_path,
                rule: rule.clone(),
                replay_report: evidence.replay,
            });
        }
        if let Some(rule) = &record.dynamic_value {
            let feedback = DynamicValueRuleFeedback {
                policy_path,
                rule: rule.clone(),
                replay_report: evidence.replay,
            };
            return if let Some(time) = &record.redis_time {
                crate::plan_dynamic_value_redis_time_rule(feedback, time.clone())
            } else if let Some(time) = &record.mysql_time {
                crate::plan_dynamic_value_mysql_time_rule(feedback, time.clone())
            } else {
                crate::plan_dynamic_value_rule(feedback)
            };
        }
        ResponseBodyRuleEvidence::FocusedE2e {
            assertion_report: evidence.assertions,
            aggregate_report: evidence.aggregate,
        }
    };
    if !record.response_jwts.is_empty() {
        return crate::plan_response_jwt_rule(crate::ResponseJwtRuleFeedback {
            policy_path,
            api: state.api.clone(),
            rules: record.response_jwts.clone(),
            evidence,
        });
    }
    crate::plan_response_header_date_rule(ResponseHeaderDateRuleFeedback {
        policy_path,
        api: super::super::api_selector::public_api(&state.api).into(),
        rules: record.header_dates.clone(),
        evidence,
    })
}
