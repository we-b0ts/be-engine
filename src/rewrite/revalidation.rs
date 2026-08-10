use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::RecordingApi;

use super::model::{
    ACTION_SCHEMA_VERSION, RewriteAction, RewriteActionEnvelope, RewriteApiStatus, RewriteState,
};
use super::store::RewriteStore;
use super::{action, fingerprint, inventory, traffic_operation};

const MAX_REASON_BYTES: usize = 512;

#[derive(Debug, Clone)]
pub struct RewriteRevalidationRequestOptions {
    pub target_root: PathBuf,
    pub apis: Vec<RecordingApi>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRevalidationRequestReport {
    pub schema_version: u32,
    pub target_fingerprint: String,
    pub requested_apis: Vec<String>,
    pub reason: String,
    pub next: RewriteActionEnvelope,
}

pub fn request(
    options: RewriteRevalidationRequestOptions,
) -> Result<RewriteRevalidationRequestReport> {
    ensure!(
        !options.apis.is_empty(),
        "early revalidation requires at least one --api"
    );
    super::validate_single_line("revalidation reason", &options.reason)?;
    ensure!(
        options.reason.len() <= MAX_REASON_BYTES,
        "revalidation reason exceeds {MAX_REASON_BYTES} bytes"
    );
    let requested = options
        .apis
        .into_iter()
        .map(|api| api.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    ensure!(
        matches!(
            traffic_operation::state(&target_root)?,
            traffic_operation::TrafficOperationState::Absent
        ),
        "early revalidation cannot be requested while a traffic operation is active"
    );
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    inventory::initialize_legacy(&mut state);
    let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
    inventory::defer_completed_for_target_change(&mut state, &target_fingerprint)?;
    promote(&mut state, &requested, &target_fingerprint)?;

    let first = requested
        .first()
        .expect("non-empty revalidation request was validated")
        .parse::<RecordingApi>()?;
    let scoped = inventory::scoped(&state, Some(&first))?;
    let next = action::for_status(&target_root, &scoped)?;
    store.save(&state)?;
    Ok(RewriteRevalidationRequestReport {
        schema_version: ACTION_SCHEMA_VERSION,
        target_fingerprint,
        requested_apis: requested,
        reason: options.reason,
        next,
    })
}

pub(super) fn deferred_status_envelope(
    target_root: &std::path::Path,
    state: &RewriteState,
    api: &RecordingApi,
) -> Result<Option<RewriteActionEnvelope>> {
    let requested = api.to_string();
    let Some(item) = state
        .api_inventory
        .iter()
        .find(|item| item.api == requested)
    else {
        return Ok(None);
    };
    if item.status != RewriteApiStatus::RevalidationPending {
        return Ok(None);
    }
    let scoped = inventory::scoped(state, Some(api))?;
    Ok(Some(action::envelope(
        target_root,
        &scoped,
        RewriteAction::WaitRequired {
            summary: format!(
                "defer final revalidation for {requested} until normal API work drains; the coordinator may request early verification when a shared change has high impact"
            ),
            resource: "rewrite_final_revalidation".to_string(),
            requested_api: Some(requested.clone()),
            blocking_api: (!state.api.is_empty()).then(|| state.api.clone()),
            active_operation: None,
            retry_after_seconds: 5,
            status: action::status_command_for_api(target_root, Some(&requested)),
        },
    )))
}

fn promote(state: &mut RewriteState, requested: &[String], target_fingerprint: &str) -> Result<()> {
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
    for item in &mut state.api_inventory {
        if requested.contains(item.api.as_str()) {
            item.status = RewriteApiStatus::Pending;
        }
    }
    state.bump();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::*;

    #[test]
    fn early_request_promotes_only_selected_stale_apis() {
        let mut state = crate::rewrite::test_state();
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

        promote(&mut state, &["POST /b".to_string()], "fnv1a64:current").unwrap();

        assert_eq!(
            state.api_inventory[0].status,
            RewriteApiStatus::RevalidationPending
        );
        assert_eq!(state.api_inventory[1].status, RewriteApiStatus::Pending);
        assert_eq!(state.api_inventory[2].status, RewriteApiStatus::Pending);
    }

    #[test]
    fn early_request_rejects_current_or_normal_pending_apis() {
        let mut state = crate::rewrite::test_state();
        inventory::install(&mut state, vec!["GET /a".to_string()]).unwrap();

        let error = promote(&mut state, &["GET /a".to_string()], "fnv1a64:current").unwrap_err();

        assert!(error.to_string().contains("not revalidation_pending"));
    }

    #[test]
    fn scoped_status_explains_that_stale_success_is_deferred() {
        let mut state = crate::rewrite::test_state();
        inventory::install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        state.api_inventory[1].status = RewriteApiStatus::RevalidationPending;

        let envelope =
            deferred_status_envelope(Path::new("/target"), &state, &"POST /b".parse().unwrap())
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
    fn request_persists_selected_early_work_and_returns_its_next_action() {
        let target = configured_target();
        let baseline = fingerprint::repository_fingerprint(target.path()).unwrap();
        let mut state = crate::rewrite::test_state();
        inventory::install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        inventory::activate_requested(&mut state, Some(&"POST /b".parse().unwrap())).unwrap();
        state.api_inventory[0].status = RewriteApiStatus::Complete;
        state.api_inventory[0].e2e_current = true;
        state.api_inventory[0].comparison_current = true;
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
            apis: vec!["GET /a".parse().unwrap()],
            reason: "shared response mapper changed".to_string(),
        })
        .unwrap();

        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["schema_version"], serde_json::json!(14));
        assert_eq!(
            value.pointer("/next/action/kind"),
            Some(&serde_json::json!("advance_required"))
        );
        assert_eq!(
            value.pointer("/next/action/commands/advance/argv/5"),
            Some(&serde_json::json!("GET /a"))
        );
        let saved = RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(saved.api_inventory[0].status, RewriteApiStatus::Pending);
        assert_eq!(saved.api_inventory[1].status, RewriteApiStatus::Active);
    }

    fn configured_target() -> tempfile::TempDir {
        let target = tempfile::tempdir().unwrap();
        fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
        fs::create_dir_all(target.path().join("src")).unwrap();
        fs::write(target.path().join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
        fs::write(
            target.path().join(".traffic-e2e/project.yaml"),
            "version: 12\n\
             source:\n  container: source\n\
             target:\n  dockerfile: .traffic-e2e/Dockerfile.e2e\n  startup: {}\n  http_host: 127.0.0.1\n  port: 8081\n  readiness_path: /healthz\n  readiness_status: 404\n  quality_gates: []\n\
             replay:\n  policy: .traffic-e2e/verification.yaml\n\
             recording:\n  config: .traffic-e2e/recorder.toml\n  rule: record-api\n\
             delivery:\n  pr_base: dev-migration\n\
             state:\n  runtime_root: local/runtime\n",
        )
        .unwrap();
        fs::write(
            target.path().join(".traffic-e2e/verification.yaml"),
            "version: 2\nexpected_response: assertions_only\nrules: []\n",
        )
        .unwrap();
        fs::write(
            target.path().join(".traffic-e2e/recorder.toml"),
            "[[http_gateway.rules]]\nname = \"record-api\"\nmethods = [\"GET\"]\npath_prefixes = [\"/\"]\n",
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
