//! Rule planning publishes immutable results independently of long Replay transactions.
//! Snapshot writers fold in newer events under a short publication lock.
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::super::{
    inventory,
    model::{RewriteRulePlanRecord, RewriteState},
    store::RewriteStore,
};

#[derive(Default, Serialize, Deserialize)]
struct Events {
    workflow_id: String,
    revision: u64,
    plans: BTreeMap<String, Event>,
}

#[derive(Serialize, Deserialize)]
struct Event {
    revision: u64,
    plan: RewriteRulePlanRecord,
}

fn root(target: &Path) -> PathBuf {
    crate::internal_runtime::root(target).join("rewrite/rule-plans")
}

pub(in crate::rewrite) fn lock(target: &Path) -> Result<File> {
    lock_file(&root(target).join("publication.lock"), false)
}

pub(in crate::rewrite) fn lock_api(target: &Path, api: &str) -> Result<File> {
    let name = super::super::fingerprint::id(&[api]).replace(':', "-");
    lock_file(&root(target).join(format!("{name}.lock")), true)
}

fn lock_file(path: &Path, nonblocking: bool) -> Result<File> {
    fs::create_dir_all(path.parent().context("rule plan lock has no directory")?)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    if nonblocking {
        file.try_lock().context("this API already has a rule planning or application operation; retry after it completes")?;
    } else {
        file.lock()
            .context("failed to lock rule plan publication")?;
    }
    Ok(file)
}

fn load(target: &Path) -> Result<Events> {
    let path = root(target).join("events.json");
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("invalid rule plan events"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Events::default()),
        Err(error) => Err(error.into()),
    }
}

pub(in crate::rewrite) fn overlay(target: &Path, state: &mut RewriteState) -> Result<()> {
    let events = load(target)?;
    if events.workflow_id != state.workflow_id || events.revision <= state.rule_plan_event_revision
    {
        return Ok(());
    }
    for slice in std::iter::once(&mut state.active_slice).chain(state.parked_slices.values_mut()) {
        if let Some(event) = events.plans.get(&slice.api)
            && event.revision > state.rule_plan_event_revision
        {
            // Retain stale plans for explicit recovery, even when a newer
            // attempt replaced the original issue. Never silently retarget one.
            slice.rule_plan = Some(event.plan.clone());
        }
    }
    state.revision = state
        .revision
        .saturating_add(events.revision - state.rule_plan_event_revision);
    state.rule_plan_event_revision = events.revision;
    Ok(())
}

pub(in crate::rewrite) fn publish(
    target: &Path,
    expected: &RewriteState,
    plan: RewriteRulePlanRecord,
) -> Result<()> {
    let _lock = lock(target)?;
    ensure_not_replaying(target, &expected.api)?;
    let current = RewriteStore::new(target)?
        .load()?
        .context("workflow disappeared during planning")?;
    ensure!(
        current.workflow_id == expected.workflow_id
            && current.recording_run_id == expected.recording_run_id,
        "workflow or recording changed during planning; obtain fresh evidence"
    );
    let current = inventory::scoped(&current, Some(&expected.api.parse()?))?;
    ensure!(
        current.active_issue.as_ref().map(|i| &i.id)
            == expected.active_issue.as_ref().map(|i| &i.id)
            && current.attempts.last().map(|a| a.attempt)
                == expected.attempts.last().map(|a| a.attempt)
            && current.group_id == expected.group_id
            && current.case_inventory_id == expected.case_inventory_id
            && current.source_revision == expected.source_revision
            && current.case_source == expected.case_source
            && current.replay_identity == expected.replay_identity,
        "API evidence changed during planning; obtain fresh evidence"
    );
    ensure!(
        current.rule_plan.as_ref().map(|p| &p.id) == expected.rule_plan.as_ref().map(|p| &p.id),
        "pending rule plan changed during planning"
    );
    plan.unified
        .as_ref()
        .context("only unified plans support concurrent publication")?
        .ensure_policy_current()?;
    let mut events = load(target)?;
    if events.workflow_id != current.workflow_id {
        events = Events {
            workflow_id: current.workflow_id.clone(),
            ..Default::default()
        };
    }
    events.revision = events
        .revision
        .max(current.rule_plan_event_revision)
        .checked_add(1)
        .context("rule plan revision overflow")?;
    events.plans.insert(
        expected.api.clone(),
        Event {
            revision: events.revision,
            plan,
        },
    );
    write(target, &events)
}

fn write(target: &Path, events: &Events) -> Result<()> {
    let directory = root(target);
    let temporary = directory.join(format!(".events-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, events)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, directory.join("events.json"))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// Caller holds publication lock and has durably saved this exact snapshot.
/// Retain only events still needed by an in-flight older snapshot or a pending
/// plan, rather than keeping full policy copies for every applied rule.
pub(in crate::rewrite) fn compact(target: &Path, state: &RewriteState) -> Result<()> {
    let mut events = load(target)?;
    if events.workflow_id != state.workflow_id {
        return Ok(());
    }
    let previous = events.plans.len();
    events.plans.retain(|api, event| {
        event.revision > state.rule_plan_event_revision
            || std::iter::once(&state.active_slice)
                .chain(state.parked_slices.values())
                .find(|slice| &slice.api == api)
                .and_then(|slice| slice.rule_plan.as_ref())
                .is_some_and(|plan| plan.id == event.plan.id)
    });
    if events.plans.len() != previous {
        write(target, &events)?;
    }
    Ok(())
}

pub(in crate::rewrite) fn ensure_not_replaying(target: &Path, api: &str) -> Result<()> {
    if let super::super::traffic_operation::TrafficOperationState::Live(active) =
        super::super::traffic_operation::state(target)?
    {
        ensure!(
            active
                .api
                .as_deref()
                .is_some_and(|selected| super::super::api_selector::public_api(selected)
                    != super::super::api_selector::public_api(api)),
            "rule evidence for {api} is unavailable while its Replay is reserved or running; wait for that attempt to finish"
        );
    }
    Ok(())
}
