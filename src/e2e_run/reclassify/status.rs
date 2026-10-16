//! Read-only shared-session classification checks, scoped to one coordinator query.
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{
    super::{E2eRunContext, config, model::RunLayout, store, support},
    ActiveRunState, RunStatus, session,
};

#[derive(Default)]
struct QuerySnapshot {
    runs: BTreeMap<(PathBuf, PathBuf), RunSnapshot>,
}

struct RunSnapshot {
    prepared_case_ids: BTreeMap<String, BTreeSet<String>>,
    states: BTreeMap<String, ActiveRunState>,
    pending_session: Option<String>,
    rules_fingerprint: String,
    sessions: BTreeMap<String, bool>,
}

#[derive(Deserialize)]
struct ReportClassification {
    #[serde(default)]
    background_reclassification: Option<Classification>,
}

#[derive(Deserialize)]
struct Classification {
    rules_fingerprint: Option<String>,
}

#[derive(Deserialize)]
struct RevisionSessions {
    previous: Vec<SessionIdentity>,
}

#[derive(Deserialize)]
struct SessionIdentity {
    session_id: Option<String>,
}

thread_local! {
    static SNAPSHOT: RefCell<Option<QuerySnapshot>> = const { RefCell::new(None) };
}

pub(crate) fn with_background_reclassification_snapshot<T>(operation: impl FnOnce() -> T) -> T {
    let owns_snapshot = SNAPSHOT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            false
        } else {
            *slot = Some(QuerySnapshot::default());
            true
        }
    });
    let _guard = SnapshotGuard { owns_snapshot };
    operation()
}

struct SnapshotGuard {
    owns_snapshot: bool,
}

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        if self.owns_snapshot {
            SNAPSHOT.with(|slot| *slot.borrow_mut() = None);
        }
    }
}

/// Detect legacy split publication without discovering cases or materializing report bodies.
pub(crate) fn focused_background_reclassification_pending(
    context: E2eRunContext,
    api: &str,
) -> Result<bool> {
    let (config, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let path = focused_state_path(&layout, api);
    if !path.is_file() || !layout.group_index_path.is_file() {
        return Ok(false);
    }
    if layout.active_dir.exists() || !store::focused_active_directories(&layout)?.is_empty() {
        return Ok(false);
    }
    SNAPSHOT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let key = (layout.run_root.clone(), layout.case_source.clone());
        if let Some(query) = slot.as_mut() {
            let snapshot = match query.runs.entry(key) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(RunSnapshot::read(&layout, &config.source_traffic_policy)?)
                }
            };
            snapshot.pending(&layout, api)
        } else {
            RunSnapshot::read(&layout, &config.source_traffic_policy)?.pending(&layout, api)
        }
    })
}

fn focused_state_path(layout: &RunLayout, api: &str) -> PathBuf {
    layout
        .run_root
        .join("focused")
        .join(support::api_directory(api))
        .join("latest/state.yaml")
}

impl RunSnapshot {
    fn read(layout: &RunLayout, policy: &Path) -> Result<Self> {
        let prepared_case_ids = crate::case_group::load_prepared_case_ids(
            &layout.group_index_path,
            &layout.case_source,
        )?;
        let mut states = BTreeMap::new();
        for api in prepared_case_ids.keys() {
            let path = focused_state_path(layout, api);
            if path.is_file() {
                states.insert(api.clone(), store::read_yaml(&path)?);
            }
        }
        let pending_path = session::revision_path(layout);
        let pending_session = if pending_path.is_file() {
            let revision: RevisionSessions = store::read_yaml(&pending_path)?;
            revision
                .previous
                .into_iter()
                .next()
                .and_then(|state| state.session_id)
        } else {
            None
        };
        let (_, fingerprints) =
            crate::config::SourceTrafficPolicyConfig::load_with_fingerprints(policy)?;
        Ok(Self {
            prepared_case_ids,
            states,
            pending_session,
            rules_fingerprint: fingerprints.classification,
            sessions: BTreeMap::new(),
        })
    }

    fn pending(&mut self, layout: &RunLayout, api: &str) -> Result<bool> {
        let primary = self
            .states
            .get(api)
            .with_context(|| format!("prepared API group not found: {api}"))?;
        // An interrupted startup can publish an attempt before Replay is ready.
        // It has no session to reclassify; retain its original failure diagnosis.
        if primary.status == RunStatus::Interrupted
            && primary.session_id.is_none()
            && !primary.replay_finalized
            && primary.case_source == layout.case_source
            && primary.run_key == layout.run_key
        {
            return Ok(false);
        }
        session::validate_primary(layout, primary)?;
        let session_id = primary
            .session_id
            .as_ref()
            .expect("validated session identity");
        if let Some(pending) = self.sessions.get(session_id) {
            return Ok(*pending);
        }
        let mut members = Vec::new();
        for (group_id, state) in &self.states {
            if state.session_id != primary.session_id {
                continue;
            }
            session::validate_projection(
                primary,
                state,
                group_id,
                self.prepared_case_ids[group_id].iter().map(String::as_str),
            )?;
            members.push(state);
        }
        let pending = if self.pending_session.as_ref() == Some(session_id) {
            true
        } else {
            split_classification(&members, &self.rules_fingerprint)?
        };
        self.sessions.insert(session_id.clone(), pending);
        Ok(pending)
    }
}

fn split_classification(members: &[&ActiveRunState], current: &str) -> Result<bool> {
    let mut fresh = false;
    let mut stale = false;
    for member in members {
        if !member.replay_report.is_file() {
            return Ok(false);
        }
        // Serde skips unrelated arrays without allocating their JSON object trees.
        let report: ReportClassification =
            serde_json::from_slice(&fs::read(&member.replay_report)?)?;
        if report
            .background_reclassification
            .and_then(|classification| classification.rules_fingerprint)
            .as_deref()
            == Some(current)
        {
            fresh = true;
        } else {
            stale = true;
        }
    }
    Ok(fresh && stale)
}

#[cfg(test)]
mod tests;
