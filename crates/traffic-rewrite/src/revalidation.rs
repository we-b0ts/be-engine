use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::RewriteApiSelector;
use crate::RecordingApi;

use super::model::{
    ACTION_SCHEMA_VERSION, RewriteAction, RewriteActionEnvelope, RewriteApiStatus, RewriteState,
};
use super::store::RewriteStore;
use super::{action, fingerprint, inventory, traffic_operation};

const MAX_REASON_BYTES: usize = 512;
mod focused;

#[derive(Debug, Clone)]
pub struct RewriteRevalidationRequestOptions {
    pub target_root: PathBuf,
    pub apis: Vec<RewriteApiSelector>,
    pub reason: String,
    pub focused: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRevalidationRequestReport {
    pub schema_version: u32,
    pub target_fingerprint: String,
    pub requested_apis: Vec<String>,
    pub reason: String,
    pub focused: bool,
    pub next: RewriteActionEnvelope,
}

pub fn request(
    options: RewriteRevalidationRequestOptions,
) -> Result<RewriteRevalidationRequestReport> {
    ensure!(
        !options.apis.is_empty(),
        "revalidation request requires at least one --api"
    );
    super::validate_single_line("revalidation reason", &options.reason)?;
    ensure!(
        options.reason.len() <= MAX_REASON_BYTES,
        "revalidation reason exceeds {MAX_REASON_BYTES} bytes"
    );
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    ensure!(
        matches!(
            traffic_operation::state(&target_root)?,
            traffic_operation::TrafficOperationState::Absent
        ),
        "revalidation cannot be requested while a traffic operation is active"
    );
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    inventory::initialize_legacy(&mut state);
    let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
    inventory::defer_completed_for_target_change(&mut state, &target_fingerprint)?;
    let mut requested = BTreeSet::new();
    for selector in &options.apis {
        let mut methods = super::api_selector::members(&state, selector);
        ensure!(
            !methods.is_empty(),
            "recorded API inventory does not contain {selector:?}"
        );
        if matches!(selector, RewriteApiSelector::Route(_)) {
            methods.retain(|api| {
                state.api_inventory.iter().any(|item| {
                    item.api == *api
                        && (item.status == RewriteApiStatus::RevalidationPending
                            || options.focused && focused::eligible(&state, item))
                })
            });
            ensure!(
                !methods.is_empty(),
                "API {selector} has no pending revalidation"
            );
        }
        requested.extend(methods);
    }
    let requested = requested.into_iter().collect::<Vec<_>>();
    if options.focused {
        focused::request(&mut state, &requested)?;
    } else {
        validate_requested(&state, &requested, &target_fingerprint)?;
    }

    let first = requested
        .first()
        .expect("non-empty revalidation request was validated")
        .parse::<RecordingApi>()?;
    let next = if let Some(deferred) = deferred_next_envelope(&target_root, &state, &first)? {
        deferred
    } else {
        action::for_status(&target_root, &state)?
    };
    store.save(&state)?;
    Ok(RewriteRevalidationRequestReport {
        schema_version: ACTION_SCHEMA_VERSION,
        target_fingerprint,
        requested_apis: requested
            .iter()
            .map(|api| super::api_selector::public_api(api).to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        reason: options.reason,
        focused: options.focused,
        next,
    })
}

pub(crate) fn focused_replay_available(state: &RewriteState) -> bool {
    focused::available(state)
}

pub(super) fn deferred_status_envelope(
    target_root: &std::path::Path,
    state: &RewriteState,
    api: &RecordingApi,
) -> Result<Option<RewriteActionEnvelope>> {
    deferred_envelope(target_root, state, api, true)
}

/// Next already owns the coordinator lock; only the scheduling gate is relevant.
pub(super) fn deferred_next_envelope(
    target_root: &std::path::Path,
    state: &RewriteState,
    api: &RecordingApi,
) -> Result<Option<RewriteActionEnvelope>> {
    deferred_envelope(target_root, state, api, false)
}

fn deferred_envelope(
    target_root: &std::path::Path,
    state: &RewriteState,
    api: &RecordingApi,
    respect_resources: bool,
) -> Result<Option<RewriteActionEnvelope>> {
    if state.revalidation_round.is_some() {
        let mut projected = state.clone();
        if super::review::pre_revalidation::reconcile(target_root, &mut projected)? {
            return deferred_envelope(target_root, &projected, api, respect_resources);
        }
    }
    let requested = api.to_string();
    let Some(item) = state
        .api_inventory
        .iter()
        .find(|item| item.api == requested)
    else {
        return Ok(None);
    };
    if (!respect_resources || !super::coordination::resources_busy(target_root)?)
        && let Some(required) =
            super::review::pre_revalidation::required_action(target_root, state)?
    {
        return Ok(Some(action::envelope(target_root, state, required)));
    }
    let outside_round = state.revalidation_round.is_some()
        && !inventory::revalidation_round::contains(state, &requested);
    if item.status != RewriteApiStatus::RevalidationPending && !outside_round {
        return Ok(None);
    }
    if !outside_round && (!respect_resources || !super::coordination::resources_busy(target_root)?)
    {
        let selected = action::for_status(target_root, state)?.action;
        if matches!(selected, RewriteAction::AdvanceRequired { api: Some(ref selected_api), .. }
            if selected_api == &requested || selected_api == super::api_selector::public_api(&requested))
        {
            return Ok(None);
        }
    }
    let scoped = inventory::scoped(state, Some(api))?;
    Ok(Some(action::envelope(
        target_root,
        &scoped,
        RewriteAction::WaitRequired {
            execution_mode: None,
            summary: format!(
                "defer {requested} until all implementations are accepted or confirmed gaps and this API is eligible in the revalidation round; finish every member before repairs or another round"
            ),
            resource: "rewrite_final_revalidation".to_string(),
            requested_api: Some(super::api_selector::public_api(&requested).into()),
            blocking_api: (!state.api.is_empty())
                .then(|| super::api_selector::public_api(&state.api).into()),
            active_operation: None,
            retry_after_seconds: 5,
            status: action::status_command_for_api(
                target_root,
                Some(super::api_selector::public_api(&requested)),
            ),
        },
    )))
}

fn validate_requested(
    state: &RewriteState,
    requested: &[String],
    target_fingerprint: &str,
) -> Result<()> {
    let requested = requested
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        requested.len() <= state.api_inventory.len(),
        "revalidation request exceeds the recorded API inventory"
    );
    for api in &requested {
        let item = state
            .api_inventory
            .iter()
            .find(|item| item.api == *api)
            .with_context(|| format!("recorded API inventory does not contain {api:?}"))?;
        ensure!(
            item.status == RewriteApiStatus::RevalidationPending,
            "API {api} is {:?}, not revalidation_pending for target fingerprint {target_fingerprint}",
            item.status
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::*;

    #[test]
    fn request_preserves_selected_stale_apis_until_round_is_ready() {
        let mut state = crate::test_state();
        inventory::install(
            &mut state,
            vec![
                "GET /a".to_string(),
                "POST /b".to_string(),
                "DELETE /c".to_string(),
            ],
        )
        .unwrap();
        state.api_inventory[0].status = RewriteApiStatus::RevalidationPending;
        state.api_inventory[1].status = RewriteApiStatus::RevalidationPending;

        validate_requested(&state, &["POST /b".to_string()], "fnv1a64:current").unwrap();

        assert_eq!(
            state.api_inventory[0].status,
            RewriteApiStatus::RevalidationPending
        );
        assert_eq!(
            state.api_inventory[1].status,
            RewriteApiStatus::RevalidationPending
        );
        assert_eq!(state.api_inventory[2].status, RewriteApiStatus::Pending);
    }

    #[test]
    fn request_rejects_current_or_normal_pending_apis() {
        let mut state = crate::test_state();
        inventory::install(&mut state, vec!["GET /a".to_string()]).unwrap();

        let error =
            validate_requested(&state, &["GET /a".to_string()], "fnv1a64:current").unwrap_err();

        assert!(error.to_string().contains("not revalidation_pending"));
    }

    #[test]
    fn scoped_status_explains_that_stale_success_is_deferred() {
        let target = configured_target();
        let mut state = crate::test_state();
        inventory::install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        state.api_inventory[1].status = RewriteApiStatus::RevalidationPending;

        let envelope = deferred_status_envelope(target.path(), &state, &"POST /b".parse().unwrap())
            .unwrap()
            .unwrap();
        let value = serde_json::to_value(envelope).unwrap();

        assert_eq!(
            value.pointer("/action/kind"),
            Some(&serde_json::json!("wait_required"))
        );
        assert_eq!(
            value.pointer("/action/details/resource"),
            Some(&serde_json::json!("rewrite_final_revalidation"))
        );
    }

    #[test]
    fn request_cannot_bypass_an_unfinished_implementation() {
        let target = configured_target();
        let baseline = fingerprint::repository_fingerprint(target.path()).unwrap();
        let mut state = crate::test_state();
        inventory::install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        inventory::activate_requested(&mut state, Some(&"POST /b".parse().unwrap())).unwrap();
        state.api_inventory[0].status = RewriteApiStatus::Complete;
        state.api_inventory[0].e2e_current = true;
        state.api_inventory[0].verified_target_fingerprint = Some(baseline);
        RewriteStore::new(target.path())
            .unwrap()
            .save(&state)
            .unwrap();
        fs::write(
            target.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )
        .unwrap();

        let report = request(RewriteRevalidationRequestOptions {
            target_root: target.path().to_path_buf(),
            apis: vec!["/a".parse().unwrap()],
            reason: "shared response mapper changed".to_string(),
            focused: false,
        })
        .unwrap();

        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            value["schema_version"],
            serde_json::json!(crate::model::ACTION_SCHEMA_VERSION)
        );
        assert_eq!(
            value.pointer("/next/action/kind"),
            Some(&serde_json::json!("wait_required"))
        );
        assert_eq!(
            value.pointer("/next/action/details/requested_api"),
            Some(&serde_json::json!("/a"))
        );
        let saved = RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(
            saved.api_inventory[0].status,
            RewriteApiStatus::RevalidationPending
        );
        assert_eq!(saved.api_inventory[1].status, RewriteApiStatus::Active);
    }

    #[test]
    fn next_uses_the_round_gate_without_waiting_on_its_own_lock() {
        let target = configured_target();
        let mut state = crate::test_state();
        inventory::install(&mut state, vec!["GET /a".into()]).unwrap();
        state.api_inventory[0].status = RewriteApiStatus::RevalidationPending;
        state.phase = crate::RewritePhase::SliceComplete;
        state.current_api_index = None;
        let store = RewriteStore::new(target.path()).unwrap();
        let _lock = store.lock().unwrap();
        let api = "GET /a".parse().unwrap();
        assert!(
            deferred_status_envelope(target.path(), &state, &api)
                .unwrap()
                .is_some()
        );
        let required = deferred_next_envelope(target.path(), &state, &api)
            .unwrap()
            .expect("the owned lock must not hide the final review stage");
        assert!(matches!(
            required.action,
            RewriteAction::PreRevalidationReviewRequired { .. }
        ));
    }

    #[tokio::test]
    async fn explicit_api_next_cannot_start_an_unreviewed_final_sweep() {
        let target = configured_target();
        let mut state = crate::test_state();
        inventory::install(&mut state, vec!["GET /a".into(), "POST /b".into()]).unwrap();
        for item in &mut state.api_inventory {
            item.status = RewriteApiStatus::RevalidationPending;
        }
        state.phase = crate::RewritePhase::SliceComplete;
        state.current_api_index = None;
        let store = RewriteStore::new(target.path()).unwrap();
        store.save(&state).unwrap();
        let result = crate::advance::advance_rewrite(crate::RewriteNextOptions {
            target_root: target.path().into(),
            api: Some("/a".parse().unwrap()),
            source_route: None,
        })
        .await
        .unwrap();
        assert!(!result.replay_can_continue);
        assert!(matches!(
            result.envelope.action,
            RewriteAction::PreRevalidationReviewRequired { .. }
        ));
        let saved = store.load().unwrap().unwrap();
        assert!(saved.attempts.is_empty());
        assert!(saved.api_inventory.iter().all(|item| item.attempts == 0));
        assert!(matches!(
            action::for_status(target.path(), &saved).unwrap().action,
            RewriteAction::PreRevalidationReviewRequired { .. }
        ));
        assert!(matches!(
            traffic_operation::state(target.path()).unwrap(),
            traffic_operation::TrafficOperationState::Absent
        ));
    }

    pub(super) fn configured_target() -> tempfile::TempDir {
        let target = tempfile::tempdir().unwrap();
        fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
        fs::create_dir_all(target.path().join("src")).unwrap();
        fs::write(target.path().join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
        crate::workflow_test_support::install_project_config(
            target.path(),
            "dev-migration",
            crate::workflow_test_support::managed_test_recorder(),
            Some(serde_json::json!([])),
        );
        fs::write(
            target.path().join(".traffic-e2e/verification.yaml"),
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        fs::write(
            target.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();
        git(target.path(), &["init", "-q", "-b", "dev-migration"]);
        git(target.path(), &["add", "."]);
        git(
            target.path(),
            &[
                "-c",
                "user.name=Traffic E2E Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-q",
                "-m",
                "baseline",
            ],
        );
        git(target.path(), &["switch", "-q", "-c", "feature"]);
        target
    }

    fn git(target_root: &Path, args: &[&str]) {
        assert!(
            Command::new("git")
                .args(args)
                .current_dir(target_root)
                .status()
                .unwrap()
                .success()
        );
    }
}
