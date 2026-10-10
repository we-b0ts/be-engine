use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use super::model::{RewriteRecorderCaptureReport, RewriteRouteReport, RewriteState};
use super::store::RewriteStore;
use super::{inventory, recorder_capture, repair, worker};
use crate::RecordingApi;

#[derive(Debug, Clone)]
pub struct RewriteRouteOptions {
    pub target_root: PathBuf,
    pub cause: RewriteRouteCause,
    pub evidence_id: String,
    pub source_ref: String,
}

#[derive(Debug, Clone)]
pub enum RewriteRouteCause {
    UnrecordedIp {
        endpoint: String,
        case_id: String,
        origin: String,
    },
    MissingRecordedResource {
        endpoint: String,
    },
    RecorderCapabilityGap {
        required_change: String,
    },
    ReplayCapabilityGap {
        required_change: String,
    },
    ExternalDataBlocker {
        required_change: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum RewriteRouteOutcome {
    CaptureInvestigation(super::ip_capture::RewriteIpCaptureReport),
    RecorderCapture(RewriteRecorderCaptureReport),
    SystemRepair(RewriteRouteReport),
}

pub fn route(options: RewriteRouteOptions) -> Result<RewriteRouteOutcome> {
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_evidence_id(&target_root, &state, &options.evidence_id)
        .context("route evidence is stale or belongs to no concurrent API work item")?;
    worker::ensure_api_confirmed(&state, &api, "routing the issue")?;
    if state.api != api {
        let requested_api = api.parse::<RecordingApi>()?;
        inventory::activate_requested(&mut state, Some(&requested_api))?;
    }
    let report = route_in_state(&target_root, &mut state, options)?;
    store.save(&state)?;
    Ok(report)
}

fn route_in_state(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteRouteOptions,
) -> Result<RewriteRouteOutcome> {
    let RewriteRouteOptions {
        cause,
        evidence_id,
        source_ref,
        ..
    } = options;
    match cause {
        RewriteRouteCause::UnrecordedIp {
            endpoint,
            case_id,
            origin,
        } => Ok(RewriteRouteOutcome::CaptureInvestigation(
            super::ip_capture::investigate(
                target_root,
                state,
                &evidence_id,
                &source_ref,
                case_id,
                endpoint,
                origin,
            )?,
        )),
        RewriteRouteCause::MissingRecordedResource { endpoint } => {
            let report = recorder_capture::plan_missing_recorded_resource(
                target_root,
                state,
                super::RewriteRecorderCapturePlanOptions {
                    evidence_id,
                    endpoint,
                    source_evidence: source_ref,
                },
            )?;
            Ok(RewriteRouteOutcome::RecorderCapture(report))
        }
        cause => {
            let (kind, required_change) = system_repair(cause);
            let report = repair::route(
                target_root,
                state,
                repair::SystemRepairRouteOptions {
                    kind: kind.to_string(),
                    evidence_id,
                    source_ref,
                    required_change,
                },
            )?;
            Ok(RewriteRouteOutcome::SystemRepair(report))
        }
    }
}

fn system_repair(cause: RewriteRouteCause) -> (&'static str, String) {
    match cause {
        RewriteRouteCause::RecorderCapabilityGap { required_change } => {
            ("recorder_capability_gap", required_change)
        }
        RewriteRouteCause::ReplayCapabilityGap { required_change } => {
            ("replay_capability_gap", required_change)
        }
        RewriteRouteCause::ExternalDataBlocker { required_change } => {
            ("external_data_blocker", required_change)
        }
        RewriteRouteCause::MissingRecordedResource { .. }
        | RewriteRouteCause::UnrecordedIp { .. } => {
            unreachable!("missing recorded resources are handled before system repair")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use super::*;
    use crate::rewrite::model::{
        RewriteAttemptDelta, RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewritePhase,
    };
    use crate::rewrite::{evidence, fingerprint};

    #[test]
    fn missing_recorded_resource_routes_to_capture_plan_without_system_repair() {
        let (target, mut state, evidence_id) = fixture(None, false);
        let rules = target
            .path()
            .join(".traffic-e2e/source-traffic-policy.yaml");
        let original_rules = fs::read_to_string(&rules).unwrap();

        let outcome = route_in_state(
            target.path(),
            &mut state,
            RewriteRouteOptions {
                target_root: target.path().to_path_buf(),
                cause: RewriteRouteCause::MissingRecordedResource {
                    endpoint: "counter.example.com".to_string(),
                },
                evidence_id,
                source_ref: "CounterService.java:88 reads the response-driving counter".to_string(),
            },
        )
        .unwrap();

        let RewriteRouteOutcome::RecorderCapture(report) = outcome else {
            panic!("missing recorded resource entered system repair")
        };
        assert_eq!(
            report.traffic_e2e_report["resource_identity"],
            "static.config+counter"
        );
        assert_eq!(report.traffic_e2e_report["changed"], true);
        assert_eq!(
            report.next_command.argv.last().map(String::as_str),
            Some(report.plan_id.as_str())
        );
        assert_eq!(state.phase, RewritePhase::ImplementationRequired);
        assert!(state.route.is_none());
        assert!(state.recorder_capture_plan.is_some());
        assert_eq!(fs::read_to_string(rules).unwrap(), original_rules);
    }

    #[test]
    fn missing_recorded_resource_rejects_a_resource_that_is_already_captured() {
        let (target, mut state, evidence_id) = fixture(Some("static.config+counter"), false);

        let error = route_in_state(
            target.path(),
            &mut state,
            RewriteRouteOptions {
                target_root: target.path().to_path_buf(),
                cause: RewriteRouteCause::MissingRecordedResource {
                    endpoint: "counter.example.com:9332".to_string(),
                },
                evidence_id,
                source_ref: "CounterService.java:88 reads counter".to_string(),
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("domains are already captured"));
        assert_eq!(state.phase, RewritePhase::ImplementationRequired);
        assert!(state.route.is_none());
        assert!(state.recorder_capture_plan.is_none());
    }

    #[test]
    fn missing_recorded_resource_requires_a_port_for_a_shared_domain() {
        let (target, mut state, evidence_id) = fixture(None, true);

        let error = route_in_state(
            target.path(),
            &mut state,
            RewriteRouteOptions {
                target_root: target.path().to_path_buf(),
                cause: RewriteRouteCause::MissingRecordedResource {
                    endpoint: "counter.example.com".to_string(),
                },
                evidence_id,
                source_ref: "CounterService.java:88 reads counter".to_string(),
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("shared by multiple Breeze resources")
        );
        assert!(state.route.is_none());
        assert!(state.recorder_capture_plan.is_none());
    }

    #[test]
    fn missing_recorded_resource_rejects_a_domain_captured_by_another_resource() {
        let (target, mut state, evidence_id) = fixture(Some("static.config+other"), true);

        let error = route_in_state(
            target.path(),
            &mut state,
            RewriteRouteOptions {
                target_root: target.path().to_path_buf(),
                cause: RewriteRouteCause::MissingRecordedResource {
                    endpoint: "counter.example.com:9332".to_string(),
                },
                evidence_id,
                source_ref: "CounterService.java:88 reads counter".to_string(),
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("not currently bypassed"));
        assert!(state.route.is_none());
        assert!(state.recorder_capture_plan.is_none());
    }

    #[test]
    fn capability_gap_still_enters_system_repair() {
        let (target, mut state, evidence_id) = fixture(None, false);

        let outcome = route_in_state(
            target.path(),
            &mut state,
            RewriteRouteOptions {
                target_root: target.path().to_path_buf(),
                cause: RewriteRouteCause::RecorderCapabilityGap {
                    required_change: "support a new dependency protocol".to_string(),
                },
                evidence_id,
                source_ref: "Client.java:42 uses the unsupported protocol".to_string(),
            },
        )
        .unwrap();

        let RewriteRouteOutcome::SystemRepair(report) = outcome else {
            panic!("capability gap did not enter system repair")
        };
        assert!(report.accepted);
        assert_eq!(state.phase, RewritePhase::SystemRepairRequired);
        assert_eq!(
            state.route.as_ref().map(|route| route.kind.as_str()),
            Some("recorder_capability_gap")
        );
        assert!(state.recorder_capture_plan.is_none());
    }

    fn fixture(
        captured_resource: Option<&str>,
        shared_domain: bool,
    ) -> (tempfile::TempDir, RewriteState, String) {
        let target = tempfile::tempdir().unwrap();
        let snapshot = target.path().join("snapshot");
        fs::create_dir(&snapshot).unwrap();
        fs::create_dir(target.path().join("src")).unwrap();
        fs::write(
            snapshot.join("static.config+counter"),
            "123\ncounter\nbackends:\n- counter.example.com:9332\n",
        )
        .unwrap();
        if shared_domain {
            fs::write(
                snapshot.join("static.config+other"),
                "123\nother\nbackends:\n- counter.example.com:9444\n",
            )
            .unwrap();
        }
        let mut recorder = crate::config::AppConfig::default();
        recorder.dns_mock.enabled = true;
        recorder.dns_mock.bypass_strategies =
            vec![crate::config::DnsBypassStrategyConfig::Breeze {
                snapshot_dir: snapshot.clone(),
                capture_resources: Vec::new(),
            }];
        crate::rewrite::test_support::install_project_config(
            target.path(),
            "master",
            recorder,
            None,
        );
        if let Some(captured_resource) = captured_resource {
            let mut rules = crate::config::SourceTrafficPolicyConfig::empty();
            rules.breeze_capture = vec![crate::config::SourceTrafficBreezeCaptureConfig {
                snapshot_dir: snapshot,
                capture_resources: vec![captured_resource.to_string()],
            }];
            fs::write(
                target
                    .path()
                    .join(".traffic-e2e/source-traffic-policy.yaml"),
                rules.render().unwrap(),
            )
            .unwrap();
        }
        fs::write(
            target.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();
        git_ok(target.path(), &["init"]);
        git_ok(target.path(), &["config", "user.email", "test@example.com"]);
        git_ok(target.path(), &["config", "user.name", "Traffic E2E Test"]);
        git_ok(target.path(), &["add", "."]);
        git_ok(target.path(), &["commit", "-m", "baseline"]);

        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.source_revision = Some("source-image-1".to_string());
        state.target_fingerprint =
            Some(fingerprint::repository_fingerprint(target.path()).unwrap());
        state.attempt_delta = Some(RewriteAttemptDelta {
            previous_attempt: 1,
            current_attempt: 2,
            response_passed_delta: 0,
            response_nonpassing_delta: 0,
            improved: false,
            regressed: false,
        });
        state.active_issue = Some(RewriteIssue {
            id: "issue-counter".to_string(),
            kind: RewriteIssueKind::Response,
            owner: RewriteIssueOwner::TargetCode,
            summary: "counter response differs".to_string(),
            pointer_pattern: None,
            representative: None,
            egress_rejections: None,
            recorder_capture_diagnosis: None,
            response_diagnosis: None,
            possible_causes: Vec::new(),
            observed_target_fingerprint: state.target_fingerprint.clone().unwrap(),
            attempt: 2,
        });
        let query_id = evidence::commands(target.path(), &state)
            .into_iter()
            .find(|command| command.query_id.contains("attempt-delta"))
            .unwrap()
            .query_id;
        let evidence_id = evidence::query(target.path(), &state, &query_id)
            .unwrap()
            .evidence_id;
        (target, state, evidence_id)
    }

    fn git_ok(repository: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "git command failed: {args:?}");
    }
}
