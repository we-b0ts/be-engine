//! One final session covers every current workflow method contract.
use super::{batch_verification, model::SCHEMA, source, workflow_verification};
use crate::rewrite::model::{
    RewriteAction, RewriteActionEnvelope, RewriteAdvanceKind, RewriteApiStatus,
    RewriteInputRequiredReason, RewritePhase, RewriteState,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};

#[cfg(test)]
mod tests;

pub(super) fn apis_ready(state: &RewriteState) -> bool {
    let reviewed_round = state
        .pre_revalidation_review
        .as_ref()
        .is_some_and(|review| !review.remaining.is_empty())
        && state.api_inventory.iter().all(|item| {
            matches!(
                item.status,
                RewriteApiStatus::Complete
                    | RewriteApiStatus::Skipped
                    | RewriteApiStatus::RevalidationPending
            ) || item.status == RewriteApiStatus::Active
                && item.api == state.api
                && state.phase == RewritePhase::ApiPending
                && crate::rewrite::inventory::revalidation_round::contains(state, &item.api)
        });
    (state.phase == RewritePhase::SliceComplete || reviewed_round)
        && !state.api_inventory.is_empty()
        && (state.revalidation_round.is_none() || reviewed_round)
        && state.group_replay.is_none()
        && state.source_review_rework.is_empty()
        && !crate::rewrite::rule_plans::pending(state)
        && (reviewed_round
            || state.api_inventory.iter().all(|item| {
                item.status == RewriteApiStatus::Skipped
                    || item.status == RewriteApiStatus::Complete && item.e2e_current
            }))
}

fn bind_source_context(root: &Path, state: &mut RewriteState) -> Result<()> {
    if state.case_source.is_none() {
        let source = crate::rewrite::artifacts::recording_run(root, &state.recording_run_id);
        crate::dependency_index::recording::manifest(&source)?;
        state.case_source = Some(source);
    }
    if state.source_revision.is_none() {
        state.source_revision = Some(crate::source_snapshot::source_image_revision(root)?);
    }
    Ok(())
}

fn input(summary: String, required: Vec<String>) -> RewriteAction {
    RewriteAction::InputRequired {
        reason: RewriteInputRequiredReason::RecordingEvidenceRequired,
        summary,
        required,
        recording_input_diagnosis: None,
    }
}

/// Coverage is an input-metadata question. Native Source attribution and actual
/// consumption remain cold checks when executing and accepting the final round.
fn validate_source_coverage(state: &RewriteState, methods: &BTreeSet<String>) -> Result<()> {
    let case_source = state
        .case_source
        .as_deref()
        .context("workflow has no Source recording")?;
    let (recording, manifest) = crate::dependency_index::recording::manifest(case_source)?;
    ensure!(
        manifest.run_id == state.recording_run_id,
        "Source recording identity differs from the current workflow"
    );
    ensure!(
        manifest.capture_complete
            && !manifest.coverage.inventory_gaps
            && manifest.coverage.capture_failures == 0
            && manifest.coverage.pending.is_empty()
            && !manifest.inputs.is_empty()
            && manifest.inputs.iter().all(|input| input.complete),
        "final workflow reconciliation requires every sealed Source input to be complete"
    );
    let selectors = methods
        .iter()
        .map(|method| {
            let api = method.parse::<crate::RecordingApi>()?;
            if let Some(route) = state
                .source_route_bindings
                .get(method)
                .map(String::as_str)
                .or_else(|| {
                    state
                        .api_inventory
                        .iter()
                        .find(|item| item.api == *method)
                        .and_then(|item| item.source_route.as_deref())
                })
            {
                crate::rewrite::inventory::validate_source_route(&api, route)?;
            }
            Ok(api)
        })
        .collect::<Result<Vec<_>>>()?;
    // The existing seal authentication cache uses native file stamps. A warm
    // status only stats sealed files; it never rebuilds the dependency Catalog.
    crate::dependency_index::recording::authenticate(&recording)?;
    crate::case_group::validate_recording_api_cases(case_source, &selectors)
}

fn source_block(root: &Path, state: &RewriteState) -> Option<RewriteAction> {
    let methods = match workflow_verification::required_scope_methods(root, state) {
        Ok(methods) => methods,
        Err(error) => {
            return Some(input(
                format!("cannot resolve current workflow method scope: {error:#}"),
                vec!["provide valid current only/skip regression selectors".into()],
            ));
        }
    };
    let current_methods = workflow_verification::methods(state);
    let capture = state
        .dependency_review
        .obligations
        .values()
        .filter(|obligation| {
            obligation.pending()
                && methods.iter().any(|method| {
                    crate::rewrite::verification_obligations::scope_matches_api(
                        &obligation.scope,
                        method,
                    )
                })
                && obligation.requirement == crate::rewrite::VerificationRequirement::Capture
                && obligation.baseline_recording_run_id == state.recording_run_id
        })
        .map(|obligation| {
            format!(
                "capture the actual origin scope {}: {}",
                serde_json::to_string(&obligation.scope).expect("scope serializes"),
                obligation.reason
            )
        })
        .collect::<Vec<_>>();
    if !capture.is_empty() {
        return Some(input("origin Source capture remains required; accepted unrelated APIs retain their independent conclusions".into(),capture));
    }
    let missing = methods
        .difference(&current_methods)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Some(input("the current sealed Source run omits required workflow methods; historical focused API snapshots cannot form one full session".into(),
            missing.into_iter().map(|api|format!("restore {api} in the current workflow inventory with complete Source inputs; recapture does not erase selected methods, only explicit only/skip can narrow scope")).collect()));
    }
    validate_source_coverage(state, &methods).err().map(|error| {
        let mut required=vec!["provide one current sealed Source run containing complete inputs for every required workflow method API".into()];
        if crate::rewrite::revalidation::focused_replay_available(state) {
            let apis=methods.iter().map(|api| crate::rewrite::api_selector::public_api(api)).collect::<BTreeSet<_>>()
                .into_iter().map(|api|format!("--api {api}")).collect::<Vec<_>>().join(" ");
            required.push(format!("To replay prior successful APIs against their existing complete cases without final acceptance, run backend-rewrite verification request --focused {apis} --reason 'verification policy changed; rerun API contracts', then follow next. The final full sweep still requires complete sealed Source evidence."));
        }
        input(format!("a current sealed Source run is required for final reconciliation: {error:#}"),required)
    })
}

pub(in crate::rewrite) fn required_action(
    root: &Path,
    state: &RewriteState,
) -> Option<RewriteAction> {
    if !apis_ready(state) || workflow_verification::current(root, state).unwrap_or(false) {
        return None;
    }
    if state.pre_revalidation_review.is_some()
        && !crate::rewrite::review::pre_revalidation::current(root, state)
    {
        return None;
    }
    let mut source_state = state.clone();
    if let Err(error) = bind_source_context(root, &mut source_state) {
        return Some(input(
            format!("final batch Source context is unavailable: {error:#}"),
            vec!["provide the current complete sealed Source run".into()],
        ));
    }
    if let Some(block) = source_block(root, &source_state) {
        return Some(block);
    }
    if let Some(failure) = state
        .dependency_review
        .workflow_failure
        .as_ref()
        .filter(|failure| {
            failure.recording_run_id == state.recording_run_id
                && failure.source_inventory_id
                    == source::inventory_identity(state).unwrap_or_default()
                && failure.replay_identity
                    == crate::rewrite::fingerprint::replay_identity(root).unwrap_or_default()
                && failure.attribution_snapshot
                    == crate::rewrite::dependency_attribution_snapshot(
                        root,
                        &state.recording_run_id,
                    )
                    .unwrap_or_default()
                && failure.method_apis == workflow_verification::methods(state)
                && failure.policy_fingerprint
                    == super::rules::load(root)
                        .map(|policy| policy.fingerprints.full)
                        .unwrap_or_default()
        })
    {
        return Some(RewriteAction::BatchDiagnosisRequired{summary:"the actual workflow-contract session has unresolved API dependency, response or coverage failures; diagnose its evidence before retrying".into(),
            evidence:json!({"completion_scope":"workflow_contracts","workflow_verified":false,"batch_verified":false,"method_results":failure.results,"evidence_error":failure.evidence_error,"owner":"coordinator","required":"Separate Source attribution, approved value rules and Target implementation defects; unmatched alone does not establish async ownership."}),
            inspect:crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"batch".into()],vec![]),retry:crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"retry-batch".into(),"--reason".into(),"<factual-repair>".into()],vec![])});
    }
    Some(RewriteAction::AdvanceRequired{summary:"execute every Case of every non-skipped workflow API method in one actual final session; startup and process debt remain independently visible".into(),
        command:crate::rewrite::action::next_command(root),api:None,kind:RewriteAdvanceKind::BatchReplay})
}

pub(in crate::rewrite) async fn run(root: &Path) -> Result<RewriteActionEnvelope> {
    let (root, store) = super::open(root)?;
    let _lock = store.lock()?;
    let mut state = store.load()?.context("rewrite workflow absent")?;
    bind_source_context(&root, &mut state)?;
    if let Some(required) = super::required_action(&root, &state) {
        return Ok(crate::rewrite::action::envelope(&root, &state, required));
    }
    ensure!(
        apis_ready(&state),
        "finish independent API implementation/acceptance before the final actual batch"
    );
    if let Some(action) = crate::rewrite::review::pre_revalidation::required_action(&root, &state)?
    {
        return Ok(crate::rewrite::action::envelope(&root, &state, action));
    }
    if let Some(action) = crate::rewrite::review::required_action(&root, &state)? {
        return Ok(crate::rewrite::action::envelope(&root, &state, action));
    }
    if let Some(action) =
        super::required_action(&root, &state).or_else(|| source_block(&root, &state))
    {
        return Ok(crate::rewrite::action::envelope(&root, &state, action));
    }
    if workflow_verification::current(&root, &state)? {
        return crate::rewrite::action::for_status(&root, &state);
    }
    let _plans = crate::rewrite::rule_plans::events::lock(&root)?;
    crate::rewrite::rule_plans::events::overlay(&root, &mut state)?;
    ensure!(
        !crate::rewrite::rule_plans::pending(&state),
        "apply or recover pending rules before reserving the batch session"
    );
    let traffic = crate::rewrite::traffic_operation::claim_current(
        &root,
        format!("batch-{}", uuid::Uuid::new_v4()),
        crate::rewrite::traffic_operation::TrafficOperationKind::Replay,
        None,
    )?;
    let _traffic = match traffic {
        crate::rewrite::traffic_operation::TrafficOperationClaim::Acquired(guard) => guard,
        crate::rewrite::traffic_operation::TrafficOperationClaim::Busy(marker) => {
            return Ok(crate::rewrite::action::envelope(
                &root,
                &state,
                crate::rewrite::traffic_operation::wait_action(&root, None, &marker),
            ));
        }
        crate::rewrite::traffic_operation::TrafficOperationClaim::Stale(_) => {
            anyhow::bail!("recover the stale traffic operation before the final batch")
        }
    };
    drop(_plans);
    let original = source::load(&state)?;
    let policy_fingerprint = super::rules::load(&root)?.fingerprints.full;
    let case_source = state.case_source.clone().context("Source absent")?;
    let context = crate::E2eRunContext {
        target_root: root.clone(),
        case_source: case_source.clone(),
        run_key: None,
    };
    let methods = workflow_verification::methods(&state);
    ensure!(
        !methods.is_empty(),
        "final workflow scope has no selected API methods"
    );
    for method_api in &methods {
        let api: crate::RecordingApi = method_api.parse()?;
        let seed = crate::case_group::resolve_recording_api_seed_member(&case_source, &api)?;
        let route = state
            .source_route_bindings
            .get(method_api)
            .cloned()
            .or_else(|| {
                state
                    .api_inventory
                    .iter()
                    .find(|item| item.api == *method_api)
                    .and_then(|item| item.source_route.clone())
            })
            .unwrap_or_else(|| api.path_pattern().into());
        crate::prepare_e2e_run(crate::E2eRunPrepareOptions {
            context: context.clone(),
            case_dir: seed,
            method: api.method().to_string(),
            source_route: route,
            pattern: api.is_dynamic().then(|| api.path_pattern().into()),
            source_revision: state
                .source_revision
                .clone()
                .context("Source revision absent")?,
        })?;
    }
    state.dependency_review.workflow_receipt = None;
    state.dependency_review.workflow_failure = None;
    state.bump();
    store.save(&state)?;
    let results = crate::e2e_run::run_e2e_apis(
        context,
        &methods.iter().cloned().collect::<Vec<_>>(),
        Some(&crate::e2e_run::ReplayIteration {
            workflow_id: state.workflow_id.clone(),
            final_round: true,
        }),
    )
    .await?;
    ensure!(
        super::rules::load(&root)?.fingerprints.full == policy_fingerprint,
        "workflow policy changed during final execution; inspect the genuine session and run the current final contracts again"
    );
    if !results.is_empty() {
        let mut prepared = crate::rewrite::api_batch::PreparedRoute {
            apis: vec![],
            slices: std::collections::BTreeMap::new(),
        };
        for actual in &results {
            let mut selected =
                crate::rewrite::inventory::scoped(&state, Some(&actual.api.parse()?))?;
            crate::rewrite::preparation::prepare_recording(&root, &mut selected)?;
            prepared.apis.push(actual.api.clone());
            prepared
                .slices
                .insert(actual.api.clone(), selected.active_slice);
        }
        crate::rewrite::api_batch::apply_results(&root, &mut state, &results, Some(&prepared))?;
    }
    let evidence_error = if results.iter().all(|result| result.passed) {
        workflow_verification::accept(&root, &mut state)
            .err()
            .map(|error| format!("{error:#}"))
    } else {
        Some("one or more current workflow methods failed actual verification".into())
    };
    if let Some(error) = evidence_error {
        state.dependency_review.workflow_failure = Some(super::model::WorkflowFailure {
            recording_run_id: state.recording_run_id.clone(),
            source_inventory_id: original.identity,
            replay_identity: crate::rewrite::batch_execution_identity(&root)?,
            attribution_snapshot: crate::rewrite::dependency_attribution_snapshot(
                &root,
                &state.recording_run_id,
            )?,
            policy_fingerprint: super::rules::load(&root)?.fingerprints.full,
            method_apis: methods,
            results,
            evidence_error: Some(error),
        });
    }
    state.bump();
    store.save(&state)?;
    drop(_traffic);
    Ok(crate::rewrite::action::envelope(
        &root,
        &state,
        required_action(&root, &state)
            .unwrap_or_else(|| crate::rewrite::action::state_action(&root, &state)),
    ))
}

pub fn dependency_attribution_batch_information(
    context: crate::rewrite::RewriteContext,
    offset: usize,
) -> Result<Value> {
    let (root, store) = super::open(&context.target_root)?;
    let state = store.load()?.context("rewrite workflow absent")?;
    let verified = batch_verification::current(&root, &state)? && !super::batch_pending(&state);
    Ok(
        json!({"schema":SCHEMA,"batch_verified":verified,"verification_unit":"whole_source",
        "completion_scope":"workflow_contracts","workflow_verified":workflow_verification::current(&root,&state)? && !workflow_verification::pending(&state),
        "workflow_method_apis":workflow_verification::methods(&state),"workflow_receipt":state.dependency_review.workflow_receipt,
        "last_failed_workflow_round":state.dependency_review.workflow_failure,
        "required_method_apis":batch_verification::required_methods(&state),"api_acceptance_ready":apis_ready(&state),
        "receipt":state.dependency_review.batch_receipt,"last_failed_actual_round":state.dependency_review.batch_failure,"next_action":required_action(&root,&state),
        "actual_requests":super::target_query::inventory(&root,&state,offset).unwrap_or_else(|error|json!({"available":false,"reason":format!("{error:#}")})),
        "rule_analysis":crate::rewrite::unified_rule::batch::information(&root,&state).unwrap_or_else(|error|json!({"available":false,"reason":format!("{error:#}")})),
        "boundary":"Workflow completion covers all current non-skipped methods in one real session. WholeSource batch_verified separately requires every Source Case, startup and process obligation; no historical sessions are stitched."}),
    )
}

pub fn retry_dependency_batch(
    context: crate::rewrite::RewriteContext,
    reason: &str,
) -> Result<Value> {
    ensure!(
        !reason.trim().is_empty() && reason.len() <= 4096,
        "batch retry requires a bounded factual repair reason"
    );
    let (root, store) = super::open(&context.target_root)?;
    let _lock = store.lock()?;
    let mut state = store.load()?.context("rewrite workflow absent")?;
    if let Some(previous) = state.dependency_review.workflow_failure.take() {
        state.bump();
        store.save(&state)?;
        return Ok(
            json!({"schema":SCHEMA,"retry_reason":reason,"completion_scope":"workflow_contracts",
            "previous_method_results":previous.results,"workflow_verified":false,"batch_verified":false,
            "next_command":crate::rewrite::action::next_command(&root),"verification":"retry requires one new complete workflow-contract session; no selected API failure is waived"}),
        );
    }
    let previous = state
        .dependency_review
        .batch_failure
        .take()
        .context("there is no failed actual batch to retry")?;
    state.bump();
    store.save(&state)?;
    Ok(
        json!({"schema":SCHEMA,"retry_reason":reason,"previous_actual_round":previous.result,"batch_verified":false,
        "next_command":crate::rewrite::action::next_command(&root),"verification":"retry requires a new complete actual session; no dependency or API failure is waived"}),
    )
}
