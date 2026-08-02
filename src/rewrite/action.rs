use crate::RecordingApi;

use super::evidence;
use super::model::{
    ACTION_SCHEMA_VERSION, RewriteAction, RewriteActionEnvelope, RewriteCommandSpec, RewritePhase,
    RewriteState, RewriteWorkflowView,
};

pub(super) fn for_state(state: &RewriteState) -> RewriteActionEnvelope {
    let workflow = Some(workflow_view(state));
    let action = match state.phase {
        RewritePhase::RecordingRequired => RewriteAction::RecordingRequired {
            summary: recording_summary(state),
            command: recording_command(state, false),
            resume: next_command(),
        },
        RewritePhase::ImplementationRequired => RewriteAction::ImplementationRequired {
            issue: state
                .active_issue
                .clone()
                .expect("implementation phase requires an issue"),
            evidence_commands: evidence::commands(state),
            acceptance: next_command(),
        },
        RewritePhase::ComparisonRecordingRequired => RewriteAction::ComparisonRecordingRequired {
            summary: state.comparison_rejection.as_ref().map_or_else(
                || format!("generate fresh comparison evidence for {}", state.api),
                |reason| {
                    format!(
                        "previous comparison recording was rejected ({reason}); generate fresh comparison evidence for {}",
                        state.api
                    )
                },
            ),
            command: recording_command(state, true),
            resume: next_command(),
        },
        RewritePhase::SystemRepairRequired => RewriteAction::SystemRepairRequired {
            issue: state
                .active_issue
                .clone()
                .expect("system repair phase requires an issue"),
            route: state.route.clone(),
        },
        RewritePhase::SliceComplete => RewriteAction::Complete {
            summary: format!(
                "API slice {} has current E2E and comparison evidence",
                state.api
            ),
            e2e_current: state.e2e_current,
            comparison_current: state.comparison_current,
        },
    };
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow,
        terminal_allowed: state.phase == RewritePhase::SliceComplete,
        action,
    }
}

fn recording_summary(state: &RewriteState) -> String {
    if let Some(reason) = &state.recording_rejection {
        return format!(
            "previous standard recording was rejected ({reason}); generate a replacement for {}",
            state.api
        );
    }
    match state.recording_request_reason {
        Some(reason) => format!(
            "fresh standard recording requested ({reason}) for {}",
            state.api
        ),
        None => format!(
            "generate one finalized standard recording for {}",
            state.api
        ),
    }
}

pub(super) fn input_required() -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow: None,
        action: RewriteAction::InputRequired {
            summary: "select one canonical API to start the rewrite workflow".to_string(),
            required: vec!["--api 'METHOD /path-or-pattern'".to_string()],
        },
        terminal_allowed: false,
    }
}

pub(super) fn source_route_required(api: &RecordingApi) -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow: None,
        action: RewriteAction::InputRequired {
            summary: format!(
                "dynamic API {api} requires a route confirmed from source registration"
            ),
            required: vec!["--source-route <confirmed-source-route>".to_string()],
        },
        terminal_allowed: false,
    }
}

pub(super) fn recovery_required() -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow: None,
        action: RewriteAction::RecoveryRequired {
            summary: "rewrite workflow is locked; execute the recovery command before retrying"
                .to_string(),
            command: recover_command(),
            resume: next_command(),
        },
        terminal_allowed: false,
    }
}

pub(super) fn workflow_view(state: &RewriteState) -> RewriteWorkflowView {
    RewriteWorkflowView {
        id: state.workflow_id.clone(),
        revision: state.revision,
        phase: state.phase,
        scope: state.api.clone(),
    }
}

fn recording_command(state: &RewriteState, comparison: bool) -> RewriteCommandSpec {
    let mut argv = vec![
        "traffic-e2e".to_string(),
        if comparison {
            "record-comparison".to_string()
        } else {
            "record".to_string()
        },
        "--target-root".to_string(),
        ".".to_string(),
        "--run-id".to_string(),
        if comparison {
            state
                .comparison_run_id
                .clone()
                .expect("comparison action requires run id")
        } else {
            state.recording_run_id.clone()
        },
        "--duration-seconds".to_string(),
        state.recording_settings.duration_seconds.to_string(),
        "--api".to_string(),
        state.api.clone(),
        "--case-limit".to_string(),
        state.recording_settings.case_limit.to_string(),
    ];
    if comparison {
        argv.push("--baseline-recheck".to_string());
    }
    RewriteCommandSpec {
        argv,
        required_env_names: vec!["TRAFFIC_E2E_ENCRYPTION_KEY_B64".to_string()],
    }
}

pub(super) fn next_command() -> RewriteCommandSpec {
    RewriteCommandSpec {
        argv: vec![
            "traffic-e2e".to_string(),
            "rewrite".to_string(),
            "next".to_string(),
        ],
        required_env_names: Vec::new(),
    }
}

pub(super) fn recover_command() -> RewriteCommandSpec {
    RewriteCommandSpec {
        argv: vec![
            "traffic-e2e".to_string(),
            "rewrite".to_string(),
            "recover".to_string(),
        ],
        required_env_names: Vec::new(),
    }
}
