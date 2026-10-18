//! Durable group rounds preserve per-route admission and comparison results.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{
    api_selector, fingerprint, inventory,
    model::{RewriteAction, RewriteApiStatus, RewritePhase, RewriteState},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupReplayKind {
    /// First observation or a pending refresh after an invalidated execution.
    Initial,
    Acceptance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupReplayResult {
    pub api: String,
    pub methods: Vec<String>,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupReplayRound {
    pub group_id: String,
    pub recording_run_id: String,
    pub target_fingerprint: String,
    pub kind: GroupReplayKind,
    pub routes: Vec<String>,
    /// Exact method admissions are frozen before the first route is executed.
    pub methods: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub results: Vec<GroupReplayResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupReplaySummary {
    pub group_id: String,
    pub recording_run_id: String,
    pub target_fingerprint: String,
    pub kind: GroupReplayKind,
    pub results: Vec<GroupReplayResult>,
    pub remaining: Vec<String>,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interruption: Option<String>,
}

impl GroupReplayRound {
    fn next(&self) -> Option<&str> {
        self.routes
            .iter()
            .find(|route| !self.results.iter().any(|result| &result.api == *route))
            .map(String::as_str)
    }

    fn summary(&self, interruption: Option<String>) -> GroupReplaySummary {
        let remaining = self
            .routes
            .iter()
            .filter(|route| !self.results.iter().any(|result| &result.api == *route))
            .cloned()
            .collect::<Vec<_>>();
        GroupReplaySummary {
            group_id: self.group_id.clone(),
            recording_run_id: self.recording_run_id.clone(),
            target_fingerprint: self.target_fingerprint.clone(),
            kind: self.kind,
            results: self.results.clone(),
            complete: remaining.is_empty() && interruption.is_none(),
            remaining,
            interruption,
        }
    }
}

fn enabled(state: &RewriteState) -> bool {
    state.implementers.is_some()
        && state.revalidation_round.is_none()
        && state.phase != RewritePhase::RecordingRequired
        && !state.api_inventory.is_empty()
}

fn group<'a>(state: &'a RewriteState, route: &str) -> Option<&'a str> {
    state
        .repository_analysis
        .as_ref()?
        .api_groups
        .get(api_selector::public_api(route))
        .map(String::as_str)
}

/// Reconcile frozen admissions after a scope or recording change, without I/O.
/// New methods remain outside this round and are considered by the next one.
pub(super) fn refresh(state: &mut RewriteState) -> bool {
    let Some(round) = state.group_replay.as_ref() else {
        return false;
    };
    let interruption = if round.recording_run_id != state.recording_run_id
        || state.phase == RewritePhase::RecordingRequired
        || state.api_inventory.is_empty()
    {
        Some("recording changed or its canonical inventory was reset")
    } else {
        let invalid = round
            .routes
            .iter()
            .filter(|route| !round.results.iter().any(|result| &result.api == *route))
            .any(|route| {
                round.methods.get(route).is_none_or(|methods| {
                    methods.is_empty()
                        || methods.iter().any(|api| {
                            !state.api_inventory.iter().any(|item| {
                                item.api == *api && item.status != RewriteApiStatus::Skipped
                            }) || group(state, api) != Some(round.group_id.as_str())
                                || api_selector::public_api(api) != route
                        })
                })
            });
        invalid.then_some("selected scope or source-backed group assignments changed")
    };
    if interruption.is_none() && round.next().is_some() {
        return false;
    }
    state.last_group_replay = Some(round.summary(interruption.map(String::from)));
    state.group_replay = None;
    state.bump();
    true
}

pub(super) fn action(target_root: &Path, state: &RewriteState) -> Option<RewriteAction> {
    if !enabled(state) {
        return None;
    }
    let round = state.group_replay.as_ref()?;
    Some(super::action::replay_advance(
        target_root,
        round.next()?,
        format!(
            "continue {:?} Replay for group {}; return its per-API results after this round",
            round.kind, round.group_id
        ),
    ))
}

/// A route can contain an untouched method and an unaccepted failed sibling.
/// Route selector ranking must choose a method present in this exact round.
pub(super) fn planned_method(state: &RewriteState, api: &str) -> bool {
    state.group_replay.as_ref().is_none_or(|round| {
        round
            .methods
            .get(api_selector::public_api(api))
            .is_some_and(|methods| methods.iter().any(|method| method == api))
    })
}

pub(super) fn dispatch_ready(state: &RewriteState, route: &str) -> bool {
    if !enabled(state) {
        return true;
    }
    let Some(group_id) = group(state, route) else {
        return false;
    };
    if state
        .group_replay
        .as_ref()
        .is_some_and(|round| round.group_id == group_id)
    {
        return false;
    }
    state.api_inventory.iter().all(|item| {
        super::regression_scope::is_skipped(state, &item.api)
            || group(state, &item.api) != Some(group_id)
            || !pending_replay(state, &item.api)
    })
}

fn pending_replay(state: &RewriteState, api: &str) -> bool {
    let Some(item) = state.api_inventory.iter().find(|item| item.api == api) else {
        return false;
    };
    if state.api == api {
        return matches!(
            state.phase,
            RewritePhase::ApiPending | RewritePhase::RecordingRequired
        );
    }
    matches!(
        item.status,
        RewriteApiStatus::Pending | RewriteApiStatus::Active
    ) && state.parked_slices.get(api).is_none_or(|slice| {
        matches!(
            slice.phase,
            RewritePhase::ApiPending | RewritePhase::RecordingRequired
        )
    })
}

fn acceptance_ready(target_root: &Path, state: &RewriteState, api: &str) -> bool {
    let Ok(parsed) = api.parse() else {
        return false;
    };
    let Ok(scoped) = inventory::scoped(state, Some(&parsed)) else {
        return false;
    };
    if scoped.phase != RewritePhase::ImplementationRequired {
        return false;
    }
    let scope = super::RewriteWorkScope::Api { api: api.into() };
    super::worker::scheduler::acceptance_gate(target_root, &scoped, &scope).is_none()
}

pub(super) fn prepare(
    target_root: &Path,
    state: &mut RewriteState,
    selected_route: &str,
) -> Result<bool> {
    if !enabled(state) {
        return Ok(false);
    }
    ensure!(
        state.api_inventory.iter().all(|item| {
            super::regression_scope::is_skipped(state, &item.api)
                || group(state, &item.api).is_some()
        }),
        "finish repository analysis and grouping for every selected API before Replay"
    );
    let selected_route = api_selector::public_api(selected_route);
    let target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    if let Some(round) = &state.group_replay
        && (round.recording_run_id != state.recording_run_id
            || round.target_fingerprint != target_fingerprint)
    {
        state.last_group_replay = Some(round.summary(Some(
            "recording or target identity changed; preserve completed results and rebuild remaining admissions"
                .into(),
        )));
        state.group_replay = None;
        state.bump();
    }
    if let Some(round) = &state.group_replay {
        ensure!(
            round.next() == Some(selected_route),
            "finish group {} Replay at API {} before selecting {}",
            round.group_id,
            round.next().unwrap_or("<complete>"),
            selected_route
        );
        return Ok(true);
    }
    let group_id = group(state, selected_route)
        .context("API must finish repository analysis and grouping before Replay")?
        .to_string();
    let kind = if state.api_inventory.iter().any(|item| {
        api_selector::public_api(&item.api) == selected_route && pending_replay(state, &item.api)
    }) {
        GroupReplayKind::Initial
    } else {
        GroupReplayKind::Acceptance
    };
    let mut methods = BTreeMap::<String, Vec<String>>::new();
    let mut routes = Vec::new();
    for item in &state.api_inventory {
        if group(state, &item.api) != Some(group_id.as_str())
            || super::regression_scope::is_skipped(state, &item.api)
        {
            continue;
        }
        let eligible = match kind {
            GroupReplayKind::Initial => pending_replay(state, &item.api),
            GroupReplayKind::Acceptance => acceptance_ready(target_root, state, &item.api),
        };
        if eligible {
            let route = api_selector::public_api(&item.api).to_string();
            if !methods.contains_key(&route) {
                routes.push(route.clone());
            }
            methods.entry(route).or_default().push(item.api.clone());
        }
    }
    ensure!(
        methods.contains_key(selected_route),
        "API {selected_route} has no admitted methods for this group Replay"
    );
    // Respect the coordinator's selected entry while preserving inventory order
    // for every other route in this frozen group round.
    routes.sort_by_key(|route| route != selected_route);
    state.group_replay = Some(GroupReplayRound {
        group_id,
        recording_run_id: state.recording_run_id.clone(),
        target_fingerprint,
        kind,
        routes,
        methods,
        results: Vec::new(),
        last_error: None,
    });
    state.bump();
    Ok(true)
}

/// Narrow route preparation to the methods admitted at the start of this round.
pub(super) fn restrict(
    state: &RewriteState,
    batch: &mut super::api_batch::PreparedRoute,
) -> Result<()> {
    let Some(round) = &state.group_replay else {
        return Ok(());
    };
    let route = api_selector::public_api(&state.api);
    let admitted = round
        .methods
        .get(route)
        .context("API is outside group Replay")?;
    batch.apis.retain(|api| admitted.contains(api));
    batch.slices.retain(|api, _| admitted.contains(api));
    ensure!(
        !batch.apis.is_empty(),
        "group Replay has no remaining admitted methods"
    );
    Ok(())
}

pub(super) fn after_replay(
    target_root: &Path,
    state: &mut RewriteState,
    replayed_route: &str,
) -> Result<bool> {
    // A passing last route can itself open the final revalidation round while
    // applying its results. Finish and clear the group transaction regardless.
    if state.implementers.is_none() {
        return Ok(false);
    }
    let Some(round) = &state.group_replay else {
        return Ok(false);
    };
    let replayed_route = api_selector::public_api(replayed_route);
    ensure!(
        round.next() == Some(replayed_route),
        "group Replay completion is out of order"
    );
    ensure!(
        round.recording_run_id == state.recording_run_id
            && round.target_fingerprint == fingerprint::repository_fingerprint(target_root)?,
        "group Replay identity changed during execution"
    );
    let methods = round.methods[replayed_route].clone();
    let passed = methods.iter().all(|api| {
        let slice = if state.api == *api {
            Some(&state.active_slice)
        } else {
            state.parked_slices.get(api)
        };
        slice.is_some_and(|slice| slice.attempts.last().is_some_and(|attempt| attempt.passed))
            || state.api_inventory.iter().any(|item| {
                item.api == *api && item.status == RewriteApiStatus::Complete && item.e2e_current
            })
    });
    let round = state.group_replay.as_mut().unwrap();
    round.results.push(GroupReplayResult {
        api: replayed_route.into(),
        methods,
        passed,
    });
    round.last_error = None;
    let next = round.next().map(String::from);
    state.last_group_replay = Some(round.summary(None));
    if let Some(next) = next {
        let selected = state.group_replay.as_ref().unwrap().methods[&next][0].parse()?;
        inventory::activate_requested(state, Some(&selected))?;
    } else {
        state.group_replay = None;
    }
    state.bump();
    Ok(state.group_replay.is_some())
}

pub(super) fn interrupted(state: &mut RewriteState, error: &anyhow::Error) -> bool {
    let Some(round) = state.group_replay.as_mut() else {
        return false;
    };
    round.last_error = Some(format!("{error:#}"));
    state.last_group_replay = Some(round.summary(round.last_error.clone()));
    state.bump();
    true
}

#[cfg(test)]
mod tests;
