//! Final whole-run traffic action after independent API acceptance.
use super::{batch_verification, model::SCHEMA, source};
use crate::rewrite::model::{
    RewriteAction, RewriteActionEnvelope, RewriteAdvanceKind, RewriteApiStatus,
    RewriteInputRequiredReason, RewritePhase, RewriteState,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

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

fn source_block(state: &RewriteState) -> Option<RewriteAction> {
    let capture = state
        .dependency_review
        .obligations
        .values()
        .filter(|obligation| {
            obligation.pending()
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
    let source=match source::load(state) {Ok(source)=>source,Err(error)=>return Some(input(format!("a current sealed Source run is required for final reconciliation: {error:#}"),vec!["provide one current sealed Source run containing every required workflow method API".into()]))};
    let missing = batch_verification::required_methods(state)
        .into_iter()
        .filter(|api| !batch_verification::covers_method(&source, api).unwrap_or(false))
        .collect::<Vec<_>>();
    (!missing.is_empty()).then(||input("the current sealed Source run omits required workflow methods; historical focused API snapshots cannot form one full session".into(),
        missing.into_iter().map(|api|format!("include complete Source inputs for {api} in the final run; scoped capture does not erase other workflow API requirements")).collect()))
}

pub(in crate::rewrite) fn required_action(
    root: &Path,
    state: &RewriteState,
) -> Option<RewriteAction> {
    if !apis_ready(state) || batch_verification::current(root, state).unwrap_or(false) {
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
    if let Some(block) = source_block(&source_state) {
        return Some(block);
    }
    if let Some(failure) = state
        .dependency_review
        .batch_failure
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
        })
    {
        return Some(RewriteAction::BatchDiagnosisRequired{summary:"the complete actual session has unresolved dependency or response failures; diagnose its evidence and repair the concrete cause before retrying".into(),
            evidence:json!({"batch_verified":false,"actual_round":failure.result,"owner":"coordinator","required":"Separate Source attribution, approved value rules and Target implementation defects; unmatched alone does not establish async ownership."}),
            inspect:crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"batch".into()],vec![]),retry:crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"retry-batch".into(),"--reason".into(),"<factual-repair>".into()],vec![])});
    }
    Some(RewriteAction::AdvanceRequired{summary:"execute one actual complete Source-run session to reconcile all Case, startup and process occurrences; API results alone do not certify the batch".into(),
        command:crate::rewrite::action::next_command(root),api:None,kind:RewriteAdvanceKind::BatchReplay})
}

pub(in crate::rewrite) async fn run(root: &Path) -> Result<RewriteActionEnvelope> {
    let (root, store) = super::open(root)?;
    let _lock = store.lock()?;
    let mut state = store.load()?.context("rewrite workflow absent")?;
    bind_source_context(&root, &mut state)?;
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
    if let Some(action) = super::required_action(&root, &state).or_else(|| source_block(&state)) {
        return Ok(crate::rewrite::action::envelope(&root, &state, action));
    }
    if batch_verification::current(&root, &state)? {
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
    let case_source = state.case_source.clone().context("Source absent")?;
    let context = crate::E2eRunContext {
        target_root: root.clone(),
        case_source: case_source.clone(),
        run_key: None,
    };
    let methods = crate::rewrite::artifacts::standard_recording_apis_for_scope(
        &root,
        &state.recording_run_id,
        vec![],
    )?;
    for method_api in methods {
        let api: crate::RecordingApi = method_api.parse()?;
        let seed = crate::case_group::resolve_recording_api_seed_member(&case_source, &api)?;
        let route = state
            .source_route_bindings
            .get(&method_api)
            .cloned()
            .or_else(|| {
                state
                    .api_inventory
                    .iter()
                    .find(|item| item.api == method_api)
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
    state.dependency_review.batch_receipt = None;
    state.dependency_review.batch_failure = None;
    state.bump();
    store.save(&state)?;
    let result = crate::run_e2e_round(context.clone()).await?;
    let results = crate::e2e_run::latest_batch_api_results(context)?
        .into_iter()
        .filter(|result| {
            state
                .api_inventory
                .iter()
                .any(|item| item.api == result.api && item.status != RewriteApiStatus::Skipped)
        })
        .collect::<Vec<_>>();
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
    if result.passed {
        batch_verification::accept(&root, &mut state)?;
    } else {
        state.dependency_review.batch_failure = Some(super::model::BatchFailure {
            recording_run_id: state.recording_run_id.clone(),
            source_inventory_id: original.identity,
            replay_identity: crate::rewrite::batch_execution_identity(&root)?,
            attribution_snapshot: crate::rewrite::dependency_attribution_snapshot(
                &root,
                &state.recording_run_id,
            )?,
            result: result.clone(),
        });
    }
    state.bump();
    store.save(&state)?;
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
        json!({"schema":SCHEMA,"batch_verified":verified,"verification_unit":"one current sealed Source run, covering every required workflow method API",
        "required_method_apis":batch_verification::required_methods(&state),"api_acceptance_ready":apis_ready(&state),
        "receipt":state.dependency_review.batch_receipt,"last_failed_actual_round":state.dependency_review.batch_failure,"next_action":required_action(&root,&state),
        "actual_requests":super::target_query::inventory(&root,&state,offset).unwrap_or_else(|error|json!({"available":false,"reason":format!("{error:#}")})),
        "rule_analysis":crate::rewrite::unified_rule::batch::information(&root,&state).unwrap_or_else(|error|json!({"available":false,"reason":format!("{error:#}")})),
        "boundary":"Independent API conclusions do not stitch historical sessions or Source runs into a whole-batch receipt."}),
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
