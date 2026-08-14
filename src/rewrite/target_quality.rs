use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;

use anyhow::{Context, Result, ensure};

use crate::RecordingApi;
use crate::e2e_run::TargetQualityGateConfig;

use super::model::{RewriteAction, RewriteActionEnvelope, RewritePhase, RewriteState};
use super::store::RewriteStore;
use super::{action, fingerprint, inventory, traffic_operation, worker};

#[path = "target_replay_isolation.rs"]
mod replay_isolation;

#[derive(Debug, Clone)]
pub struct RewriteTargetQualityOptions {
    pub target_root: std::path::PathBuf,
    pub gate_id: String,
    pub api: RecordingApi,
    pub hardcode_ai_verified: Vec<String>,
}

pub fn run(options: RewriteTargetQualityOptions) -> Result<RewriteActionEnvelope> {
    let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    ensure!(
        matches!(
            traffic_operation::state(&target_root)?,
            traffic_operation::TrafficOperationState::Absent
        ),
        "target quality gates cannot run while a traffic operation is active"
    );
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let scoped = inventory::scoped(&state, Some(&options.api))?;
    ensure!(
        scoped.phase == RewritePhase::ImplementationRequired,
        "API {} is in {:?}, not implementation_required",
        scoped.api,
        scoped.phase
    );
    ensure!(
        worker::current_is_confirmed(&scoped),
        "target quality gates require the current dedicated subagent confirmation"
    );
    let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
    ensure!(
        scoped.target_fingerprint.as_deref() != Some(target_fingerprint.as_str()),
        "target repository has not changed since the latest focused attempt"
    );
    let expected = id(&scoped, &target_fingerprint, &project.target_quality_gates)?;
    ensure!(
        options.gate_id == expected,
        "target quality gate id is stale; inspect `backend-rewrite status --api '{}'`",
        scoped.api
    );

    let replay_isolation = replay_isolation::inspect(
        &target_root,
        &project.pr_base,
        &options.hardcode_ai_verified,
    )?;
    ensure!(
        replay_isolation.passed(),
        "target replay isolation gate failed:\n{}",
        serde_json::to_string_pretty(&replay_isolation)?
    );
    execute(&target_root, &project.target_quality_gates)?;
    let verified_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
    ensure!(
        verified_fingerprint == target_fingerprint,
        "target repository changed while quality gates were running; inspect status and execute the newly issued gate"
    );
    state.target_quality_fingerprint = Some(verified_fingerprint);
    state.bump();
    store.save(&state)?;
    let scoped = inventory::scoped(&state, Some(&options.api))?;
    Ok(action::advance_envelope(
        &target_root,
        &scoped,
        "target repository quality gates passed for the integrated revision; advance focused replay"
            .to_string(),
    ))
}

pub(super) fn required_action(
    target_root: &Path,
    state: &RewriteState,
    target_fingerprint: &str,
    gates: &[TargetQualityGateConfig],
) -> Result<Option<RewriteAction>> {
    if state.target_fingerprint.as_deref() == Some(target_fingerprint)
        || state.target_quality_fingerprint.as_deref() == Some(target_fingerprint)
    {
        return Ok(None);
    }
    let gate_id = id(state, target_fingerprint, gates)?;
    Ok(Some(RewriteAction::TargetQualityRequired {
        summary: format!(
            "run {} target repository quality gate(s) in the integrated coordinator worktree before focused replay",
            gates.len() + 1
        ),
        gate_id: gate_id.clone(),
        target_fingerprint: target_fingerprint.to_string(),
        gates: std::iter::once(replay_isolation::GATE_NAME.to_string())
            .chain(gates.iter().map(|gate| gate.name.clone()))
            .collect(),
        command: action::command(
            target_root,
            vec![
                "target-quality".to_string(),
                "run".to_string(),
                gate_id,
                "--api".to_string(),
                state.api.clone(),
            ],
            Vec::new(),
        ),
    }))
}

pub(super) fn status_action(
    target_root: &Path,
    state: &RewriteState,
) -> Result<Option<RewriteAction>> {
    if state.phase != RewritePhase::ImplementationRequired {
        return Ok(None);
    }
    let target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    if state.target_fingerprint.as_deref() == Some(target_fingerprint.as_str()) {
        return Ok(None);
    }
    let project_config = target_root.join(".traffic-e2e/project.yaml");
    let gates = if project_config.is_file() {
        crate::e2e_run::resolve_project(target_root)?
            .1
            .target_quality_gates
    } else {
        Vec::new()
    };
    if !worker::current_is_confirmed(state) {
        return Ok(None);
    }
    if let Some(action) = required_action(target_root, state, &target_fingerprint, &gates)? {
        return Ok(Some(action));
    }
    Ok(Some(RewriteAction::AdvanceRequired {
        summary: "target repository quality gates are current; advance coordinator verification"
            .to_string(),
        command: action::next_command_for_api(target_root, &state.api),
    }))
}

fn id(
    state: &RewriteState,
    target_fingerprint: &str,
    gates: &[TargetQualityGateConfig],
) -> Result<String> {
    let serialized = serde_json::to_string(gates)?;
    let digest = fingerprint::id(&[
        "rewrite-target-quality-v2",
        &state.workflow_id,
        &state.api,
        target_fingerprint,
        replay_isolation::GATE_VERSION,
        &serialized,
    ]);
    Ok(format!("target-quality-{}", digest.replace(':', "-")))
}

fn execute(target_root: &Path, gates: &[TargetQualityGateConfig]) -> Result<()> {
    for gate in gates {
        let mut child = Command::new(&gate.argv[0])
            .args(&gate.argv[1..])
            .current_dir(target_root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to start target quality gate {:?}", gate.name))?;
        let mut stdout = child
            .stdout
            .take()
            .context("target quality gate stdout pipe is unavailable")?;
        let forward = thread::spawn(move || io::copy(&mut stdout, &mut io::stderr()));
        let status = child
            .wait()
            .with_context(|| format!("failed to wait for target quality gate {:?}", gate.name))?;
        forward
            .join()
            .map_err(|_| anyhow::anyhow!("target quality gate output forwarding panicked"))??;
        ensure!(
            status.success(),
            "target quality gate {:?} failed with {status}",
            gate.name
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::rewrite::model::{
        RewriteApiProgress, RewriteApiStatus, RewriteIssue, RewriteIssueKind, RewriteIssueOwner,
    };

    fn gate(name: &str, argv: &[&str]) -> TargetQualityGateConfig {
        TargetQualityGateConfig {
            name: name.to_string(),
            argv: argv.iter().map(|value| (*value).to_string()).collect(),
        }
    }

    fn target_issue() -> RewriteIssue {
        RewriteIssue {
            id: "issue-target".to_string(),
            kind: RewriteIssueKind::Response,
            owner: RewriteIssueOwner::TargetCode,
            summary: "target response differs".to_string(),
            pointer_pattern: Some("/result".to_string()),
            representative: None,
            response_diagnosis: None,
            possible_causes: vec!["target behavior differs".to_string()],
            observed_target_fingerprint: "fnv1a64:observed".to_string(),
            attempt: 1,
            comparison_observation: None,
        }
    }

    #[test]
    fn required_action_binds_the_integrated_worktree_and_gate_identity() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.target_fingerprint = Some("fnv1a64:old".to_string());
        let gates = vec![gate("check", &["git", "diff", "--check"])];
        let target = Path::new("/canonical/coordinator-worktree");

        let action = required_action(target, &state, "fnv1a64:new", &gates)
            .unwrap()
            .unwrap();
        let value = serde_json::to_value(action).unwrap();

        assert_eq!(
            value.pointer("/kind"),
            Some(&serde_json::json!("target_quality_required"))
        );
        assert_eq!(
            value.pointer("/commands/execute/cwd"),
            Some(&serde_json::json!(target))
        );
        assert_eq!(
            value.pointer("/commands/execute/argv/2"),
            Some(&serde_json::json!(target))
        );
        assert_eq!(
            value.pointer("/commands/execute/argv/3"),
            Some(&serde_json::json!("target-quality"))
        );
        assert_eq!(
            value.pointer("/commands/execute/argv/7"),
            Some(&serde_json::json!("GET /api"))
        );
        assert_eq!(
            value.pointer("/details/gates"),
            Some(&serde_json::json!(["replay-isolation", "check"]))
        );
    }

    #[test]
    fn replay_isolation_remains_required_without_configured_gates() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.target_fingerprint = Some("fnv1a64:old".to_string());

        let action = required_action(Path::new("/target"), &state, "fnv1a64:new", &[])
            .unwrap()
            .unwrap();
        let value = serde_json::to_value(action).unwrap();

        assert_eq!(
            value.pointer("/details/gates"),
            Some(&serde_json::json!(["replay-isolation"]))
        );
    }

    #[test]
    fn passed_fingerprint_suppresses_the_same_quality_action() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.target_fingerprint = Some("fnv1a64:old".to_string());
        state.target_quality_fingerprint = Some("fnv1a64:new".to_string());

        assert!(
            required_action(
                Path::new("/target"),
                &state,
                "fnv1a64:new",
                &[gate("check", &["git", "diff", "--check"])]
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn execute_uses_the_target_root_and_stops_on_failure() {
        let target = tempfile::tempdir().unwrap();
        fs::write(target.path().join("tracked"), "ok\n").unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .current_dir(target.path())
                .status()
                .unwrap()
                .success()
        );

        execute(
            target.path(),
            &[gate("inside-target", &["git", "diff", "--quiet"])],
        )
        .unwrap();
        let error = execute(target.path(), &[gate("failure", &["false"])]).unwrap_err();
        assert!(error.to_string().contains("failure"));
    }

    #[test]
    fn run_rejects_replay_details_and_does_not_persist_the_fingerprint() {
        let target = configured_target();
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.active_issue = Some(target_issue());
        state.target_fingerprint =
            Some(fingerprint::repository_fingerprint(target.path()).unwrap());
        worker::confirm_current_for_test(&mut state);
        RewriteStore::new(target.path())
            .unwrap()
            .save(&state)
            .unwrap();
        fs::write(
            target.path().join("src/lib.rs"),
            "pub const CACHE: &str = \"secret-cache.trp.test:15138\";\n",
        )
        .unwrap();

        let api = "GET /api".parse().unwrap();
        let status = super::super::status_rewrite_for_api(
            super::super::RewriteContext {
                target_root: target.path().to_path_buf(),
            },
            Some(&api),
        )
        .unwrap();
        let status = serde_json::to_value(status).unwrap();
        let gate_id = status
            .pointer("/action/details/gate_id")
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_string();

        let error = run(RewriteTargetQualityOptions {
            target_root: target.path().to_path_buf(),
            gate_id,
            api,
            hardcode_ai_verified: Vec::new(),
        })
        .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("target replay isolation gate failed"));
        assert!(message.contains("replay_hostname"));
        assert!(message.contains("src/lib.rs"));
        assert!(!message.contains("secret-cache"));
        let saved = RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert!(saved.target_quality_fingerprint.is_none());
    }

    #[test]
    fn run_persists_repository_gate_and_advances_the_selected_api() {
        let target = configured_target();
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.active_issue = Some(target_issue());
        state.target_fingerprint =
            Some(fingerprint::repository_fingerprint(target.path()).unwrap());
        state.recording_apis = vec!["GET /api".to_string(), "POST /other".to_string()];
        state.api_inventory = vec![
            RewriteApiProgress {
                api: "GET /api".to_string(),
                source_route: Some("/api".to_string()),
                status: RewriteApiStatus::Active,
                attempts: 1,
                e2e_current: false,
                comparison_current: false,
                verified_target_fingerprint: state.target_fingerprint.clone(),
            },
            RewriteApiProgress {
                api: "POST /other".to_string(),
                source_route: Some("/other".to_string()),
                status: RewriteApiStatus::Pending,
                attempts: 0,
                e2e_current: false,
                comparison_current: false,
                verified_target_fingerprint: None,
            },
        ];
        state.current_api_index = Some(0);
        worker::confirm_current_for_test(&mut state);
        inventory::activate_requested(&mut state, Some(&"POST /other".parse().unwrap())).unwrap();
        assert_eq!(state.api, "POST /other");
        RewriteStore::new(target.path())
            .unwrap()
            .save(&state)
            .unwrap();
        fs::write(
            target.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )
        .unwrap();
        let current = fingerprint::repository_fingerprint(target.path()).unwrap();
        let api = "GET /api".parse().unwrap();
        let status = super::super::status_rewrite_for_api(
            super::super::RewriteContext {
                target_root: target.path().to_path_buf(),
            },
            Some(&api),
        )
        .unwrap();
        let status = serde_json::to_value(status).unwrap();
        assert_eq!(
            status.pointer("/action/kind"),
            Some(&serde_json::json!("target_quality_required"))
        );
        assert_eq!(
            status.pointer("/action/commands/execute/argv/7"),
            Some(&serde_json::json!("GET /api"))
        );
        let gate_id = status
            .pointer("/action/details/gate_id")
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_string();

        let result = run(RewriteTargetQualityOptions {
            target_root: target.path().to_path_buf(),
            gate_id,
            api,
            hardcode_ai_verified: Vec::new(),
        })
        .unwrap();
        let value = serde_json::to_value(result).unwrap();

        assert_eq!(
            value.pointer("/action/kind"),
            Some(&serde_json::json!("advance_required"))
        );
        assert_eq!(
            value.pointer("/action/commands/advance/argv/5"),
            Some(&serde_json::json!("GET /api"))
        );
        let saved = RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(
            saved.target_quality_fingerprint.as_deref(),
            Some(current.as_str())
        );
    }

    fn configured_target() -> tempfile::TempDir {
        let target = tempfile::tempdir().unwrap();
        fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
        fs::create_dir_all(target.path().join("src")).unwrap();
        fs::write(target.path().join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
        crate::rewrite::test_support::install_project_config(
            target.path(),
            "dev-migration",
            crate::rewrite::test_support::managed_test_recorder(),
            Some(serde_json::json!([{
                "name": "diff-check",
                "argv": ["git", "diff", "--check"]
            }])),
        );
        fs::write(
            target.path().join(".traffic-e2e/verification.yaml"),
            "version: 2\nexpected_response: assertions_only\nrules: []\n",
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
