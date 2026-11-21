//! Source-only owner rules can be published before the first genuine Replay.
use super::*;
use serde_json::Value;

const PREFIX: &str = "attribution-evidence-";
#[cfg(test)]
mod tests;

pub use traffic_rewrite_model::rewrite::unified_rule::attribution::Identity;

pub use traffic_rewrite_rules::rewrite::unified_rule::attribution::IdentityMethods;
pub(crate) fn information(root: &Path, state: &RewriteState) -> Result<Value> {
    let id = Identity::current(state)?.evidence_id()?;
    Ok(
        json!({"evidence_id":id,"scope":"source_attribution","owner":"coordinator",
        "target_observations":false,"accepted":false,
        "allowed":"Source-proven process task ownership and async_api lifecycle rules only; apply independent attribution proof afterwards, then execute genuine Replay",
        "after_analysis":{
            "missing_or_incomplete_policy":"After completing ownership analysis, return a minimal rule proposal from the established Source proof and complete effective Case tail. The coordinator plans and applies it with this evidence, obtains fresh attribution context, then rebinds and applies the already established exact-occurrence proof; fresh context does not require repeating ownership analysis.",
            "existing_policy_sufficient":"Identify the effective rules and explain why they cover the Source path. No unchanged plan/apply is required; retain exact-occurrence proof for historical recordings or policy-execution gaps.",
            "async_api_scope":"For each analyzed origin, combine original Case dependencies with newly assigned occurrences, identify the actual request/response scenario, and generate end request templates, reply/message conditions and matching counts from its final business traffic. Count from Case admission, not just the newly assigned tail. Generalize task-specific values and check earlier matches. Existing coverage needs no duplicate end; do not enumerate intermediate requests or require a new Source completion signal.",
            "async_api_ending":{
                "authoring":"Write lifecycle rules under recording.async_api, before recording.case_paths when both are present. The fields are independent. Do not emit a second root async_api declaration; the logical capture.async_api identity and async_api replacement section remain unchanged.",
                "matching":"End entries are alternatives: a partial match can enter ending without requiring every end. Track each end's qualifying completion independently, including occurrence counts and transaction commit boundaries.",
                "all_conditions_matched":"Once every end in the selected scenario has matched, close new dependency admission immediately and drain admitted requests. A scenario with one end follows this same rule; no silence interval is required.",
                "partial_match":"While some ends remain unmatched, each fresh end match permits a fixed 1000 ms probe with admission open. Any later relevant request start cancels one-second closure eligibility: another fresh end match restores the probe, or closes immediately if all ends are now matched. Otherwise use the five-minute business-idle fallback. Close after a successful probe only when no relevant requests remain in flight. Repeated observation of the same exchange is not a fresh match.",
                "waiting":"After the complete primary response, waiting for the first or next end has no absolute deadline. When no fresh end arrives, 300000 ms of relevant business I/O silence with no relevant request in flight closes the Case normally, recording that completion was not observed. Activity restarts this idle interval; writer queues and definite process traffic do not. An uncovered end never stops Source or becomes a timeout failure. The primary HTTP transport timeout remains separate; explicit shutdown or actual capture failure may interrupt observation.",
                "process_traffic":"Only unambiguously identified process-owned traffic is excluded from business activity. Unknown ownership is not proof of process ownership.",
                "configuration":"Timing is fixed by the engine; do not author post_window_ms, post_windows_ms or a per-rule timeout.",
                "redis_response":{"field":"redis.when_response","kinds":["any","nil"],"default":"any","meaning":"A successful complete native Redis reply; nil is a protocol null, not a string, JSON null or missing capture."},
                "redis_message":"redis.when_message matches PUBLISH request JSON, independently of its successful integer reply."
            },
            "unavailable_terminal_or_execution_gap":"Report missing evidence or unsupported selectors and remaining recording obligations. Continue supported independent attribution and genuine Replay; do not invent a terminal event, infer ownership from a last timestamp, or add an engine-repair prerequisite."
        },
        "plan_command":action::command(root,vec!["rule".into(),"plan".into(),"--file".into(),"<source-owner-rule.yaml>".into(),"--evidence".into(),id],vec![])}),
    )
}

pub(super) fn matches(id: &str) -> bool {
    id.starts_with(PREFIX)
}

pub(super) fn plan(
    context: RewriteContext,
    options: RewriteUnifiedRulePlanOptions,
) -> Result<RewriteRuleReport> {
    let (root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&root)?;
    let _lock = store.lock()?;
    let mut state = store.load()?.context("rewrite workflow absent")?;
    ensure!(
        matches!(
            super::super::traffic_operation::state(&root)?,
            super::super::traffic_operation::TrafficOperationState::Absent
        ),
        "finish or recover traffic execution before publishing Source ownership rules"
    );
    ensure!(
        options.evidence_id == Identity::current(&state)?.evidence_id()?,
        "Source attribution assignment or inventory changed; obtain fresh attribution context"
    );
    let _plan_lock = super::super::rule_plans::events::lock_api(&root, &state.api)?;
    let result = super::plan(&root, &mut state, options, false)?;
    store.save(&state)?;
    Ok(result)
}
