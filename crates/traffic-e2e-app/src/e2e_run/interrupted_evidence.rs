//! Preserve failed execution diagnostics before the Replay process is stopped.
use anyhow::{Result, ensure};

use super::{
    final_evidence::build_final_evidence_from_current_report,
    model::{ActiveRunState, ResolvedProjectConfig, RunLayout},
    runtime::{control, stop_target_runtime},
};
use crate::case_group::CaseGroupInventory;

pub(super) async fn preserve(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    inventory: &CaseGroupInventory,
    state: &mut ActiveRunState,
) -> Result<()> {
    if state.session_id.is_none() || state.replay_finalized {
        return Ok(());
    }
    // Stop Target before freezing observations; ordinary error cleanup remains
    // responsible for any runtime that cannot stop cleanly.
    if state.target_started
        && let Err(error) = stop_target_runtime(layout, state).await
    {
        state.push_error(format!(
            "target stop before interrupted evidence failed: {error:#}"
        ));
    }
    let response = control(state, "interrupt", None, false, false).await?;
    ensure!(
        response["interrupted"] == true
            && response["finalized"] == false
            && response["complete"] == false,
        "Replay did not acknowledge an incomplete diagnostic snapshot"
    );
    build_final_evidence_from_current_report(config, layout, inventory, state)?;
    ensure!(
        !state.replay_finalized && !state.aggregate_complete,
        "interrupted evidence cannot become a completed Replay"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_run::{
        model::{CaseStatus, RunStatus},
        store, test_session,
    };
    use serde_json::{Value, json};
    use tokio::{
        io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
        net::UnixListener,
    };

    #[tokio::test]
    async fn interrupted_projection_publishes_executed_assertions_and_incomplete_dependency_evidence()
     {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let (layout, inventory, mut state) = test_session::session(root);
        let config = test_session::config(root);
        state.status = RunStatus::Interrupted;
        state.replay_finalized = false;
        state.cases[0].assertion_passed = Some(false);
        state.cases[1].status = CaseStatus::Pending;
        state.cases[1].assertion_passed = None;
        state.cases[1].replay_clean = None;
        let mut report: Value =
            serde_json::from_slice(&std::fs::read(&state.replay_report).unwrap()).unwrap();
        report["finalized"] = false.into();
        report.as_object_mut().unwrap().remove("finalized_at");
        report["interrupted"] = true.into();
        report["complete"] = false.into();
        report["active_case_id"] = "get-case".into();
        report["cases"][0]["status"] = "active".into();
        report["cases"][1]["status"] = "pending".into();
        let socket = root.join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        store::write_json(&state.replay_session, &json!({"control_socket":socket})).unwrap();
        let report_path = state.replay_report.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap()["command"],
                "interrupt"
            );
            store::write_json(&report_path, &report).unwrap();
            reader
                .into_inner()
                .write_all(
                    b"{\"ok\":true,\"interrupted\":true,\"finalized\":false,\"complete\":false}\n",
                )
                .await
                .unwrap();
        });
        preserve(&config, &layout, &inventory, &mut state)
            .await
            .unwrap();
        server.await.unwrap();
        assert!(!state.replay_finalized && !state.aggregate_complete);
        assert!(state.apis.iter().all(|api| !api.complete_pass));
        let assertions: Value =
            serde_json::from_slice(&std::fs::read(&state.assertions_report).unwrap()).unwrap();
        assert_eq!(assertions["cases"].as_array().unwrap().len(), 1);
        assert_eq!(assertions["cases"][0]["passed"], false);
        let published_root = root.join("published");
        store::publish_snapshot(&layout.active_dir, &published_root, &state).unwrap();
        let published: ActiveRunState =
            store::read_yaml(&published_root.join("state.yaml")).unwrap();
        let aggregate: Value =
            serde_json::from_slice(&std::fs::read(&published.aggregate_report).unwrap()).unwrap();
        assert_eq!(aggregate["complete"], false);
        assert_eq!(aggregate["reports"][0]["finalized"], false);
        let dirty = crate::e2e_run::dirty_evidence::build(&published, false, true).unwrap();
        assert!(!dirty.complete && dirty.dirty);
        assert!(!dirty.clusters.is_empty());
        assert_eq!(published.cases[1].status, CaseStatus::Pending);
    }
}
