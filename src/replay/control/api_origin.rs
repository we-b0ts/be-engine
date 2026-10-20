//! Wait for a finite recorded API-origin tail, without inventing Target calls.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use tokio::time::Instant;
use uuid::Uuid;

use super::super::{ReplayExchangeStatus, ReplaySource, ReplayState};
use std::sync::Arc;
use tokio::sync::Mutex;

const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SELECTED_REFS: usize = 100_000;
const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Default)]
pub(in crate::replay) struct CaseTails {
    cases: BTreeMap<String, Option<CaseTail>>,
}

#[derive(Debug, Clone)]
struct CaseTail {
    budget: Duration,
    deadline: Option<Instant>,
    selected: Vec<SelectedExchange>,
}

#[derive(Debug, Clone, Copy)]
enum SelectedExchange {
    Redis(usize),
    Mysql(usize),
}

#[derive(Deserialize)]
struct Metadata {
    version: u32,
    request_timeout_ms: u64,
    selected_completed_refs: Vec<RecordedReference>,
    #[serde(default)]
    inventory_complete: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Protocol {
    Redis,
    Mysql,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
struct RecordedReference {
    protocol: Protocol,
    connection_id: Uuid,
    sequence: u64,
}

/// Prepare immutable references before activation, without starting a Target
/// budget for a begin that may still lose concurrent case admission.
pub(in crate::replay) async fn prepare(
    state: &Arc<Mutex<ReplayState>>,
    case_id: &str,
) -> Result<()> {
    let path = {
        let state = state.lock().await;
        if state.api_origin_tails.cases.contains_key(case_id) {
            return Ok(());
        }
        state
            .cases
            .get(case_id)
            .context("API-origin tail has no replay case")?
            .dir
            .join("api-origin-observation.json")
    };
    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) => {
            ensure!(
                metadata.is_file(),
                "API-origin observation is not a regular file"
            );
            ensure!(
                metadata.len() <= MAX_METADATA_BYTES,
                "API-origin observation exceeds its metadata bound"
            );
            let raw = tokio::fs::read(&path)
                .await
                .context("failed to read API-origin observation")?;
            ensure!(
                raw.len() as u64 <= MAX_METADATA_BYTES,
                "API-origin observation exceeds its metadata bound"
            );
            let metadata: Metadata =
                serde_json::from_slice(&raw).context("invalid API-origin observation metadata")?;
            ensure!(
                metadata.version == 1,
                "unsupported API-origin observation version"
            );
            ensure!(
                metadata.inventory_complete != Some(false),
                "API-origin selected exchange inventory is incomplete"
            );
            ensure!(
                metadata.request_timeout_ms > 0,
                "API-origin observation requires a nonzero absolute request budget"
            );
            ensure!(
                metadata.selected_completed_refs.len() <= MAX_SELECTED_REFS,
                "API-origin selected exchange inventory exceeds its bound"
            );
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("failed to inspect API-origin observation"),
    };
    let mut state = state.lock().await;
    if state.api_origin_tails.cases.contains_key(case_id) {
        return Ok(());
    }
    let tail = metadata
        .map(|metadata| {
            let mut seen = BTreeSet::new();
            for reference in &metadata.selected_completed_refs {
                ensure!(
                    seen.insert(reference),
                    "API-origin observation repeats a selected exchange reference"
                );
            }
            let selected = resolve(&state, case_id, &metadata.selected_completed_refs)?;
            let budget = Duration::from_millis(metadata.request_timeout_ms);
            Ok::<_, anyhow::Error>(CaseTail {
                budget,
                deadline: None,
                selected,
            })
        })
        .transpose()?;
    state.api_origin_tails.cases.insert(case_id.into(), tail);
    Ok(())
}

/// Linearize the monotonic anchor with active-case admission. A repeated begin
/// on an already active case cannot renew the same deadline.
pub(in crate::replay) fn activate(state: &mut ReplayState, case_id: &str) -> Result<()> {
    if let Some(Some(tail)) = state.api_origin_tails.cases.get_mut(case_id)
        && tail.deadline.is_none()
    {
        tail.deadline = Some(
            Instant::now()
                .checked_add(tail.budget)
                .context("API-origin absolute request budget is out of range")?,
        );
    }
    Ok(())
}

pub(super) async fn deadline(state: &Arc<Mutex<ReplayState>>, case_id: &str) -> Option<Instant> {
    state
        .lock()
        .await
        .api_origin_tails
        .cases
        .get(case_id)
        .and_then(Option::as_ref)
        .and_then(|tail| tail.deadline)
}

fn resolve(
    state: &ReplayState,
    case_id: &str,
    references: &[RecordedReference],
) -> Result<Vec<SelectedExchange>> {
    let keys = |protocol| {
        references
            .iter()
            .filter(|reference| reference.protocol == protocol)
            .map(|reference| (reference.connection_id, reference.sequence))
            .collect::<BTreeSet<_>>()
    };
    let redis = state
        .redis
        .case_wire_exchange_indices(case_id, &keys(Protocol::Redis))?;
    let mysql_keys = keys(Protocol::Mysql);
    let mut mysql = BTreeMap::new();
    for (index, exchange) in state.mysql.exchanges.iter().enumerate() {
        let Some(key) = exchange
            .record
            .connection_id
            .zip(exchange.record.query_sequence)
        else {
            continue;
        };
        if exchange.source == ReplaySource::Case
            && exchange.case_id.as_deref() == Some(case_id)
            && mysql_keys.contains(&key)
        {
            ensure!(
                mysql.insert(key, index).is_none(),
                "API-origin MySQL reference is ambiguous in its Case semantic dependencies"
            );
        }
    }
    ensure!(
        mysql.len() == mysql_keys.len(),
        "API-origin MySQL reference is absent from its Case semantic dependencies"
    );
    Ok(references
        .iter()
        .map(|reference| {
            let key = &(reference.connection_id, reference.sequence);
            match reference.protocol {
                Protocol::Redis => SelectedExchange::Redis(redis[key]),
                Protocol::Mysql => SelectedExchange::Mysql(mysql[key]),
            }
        })
        .collect())
}

/// Only real consumption satisfies these obligations. Available entries keep
/// the case open for later Target work; failures keep the case isolated.
pub(super) async fn drain(state: &Arc<Mutex<ReplayState>>, case_id: &str) -> Result<()> {
    let tail = state
        .lock()
        .await
        .api_origin_tails
        .cases
        .get(case_id)
        .cloned()
        .flatten();
    let Some(mut tail) = tail else {
        return Ok(());
    };
    let deadline = tail
        .deadline
        .context("API-origin case budget was not activated")?;
    loop {
        let state = state.lock().await;
        ensure!(
            state.active_case_id.as_deref() == Some(case_id),
            "API-origin case ownership changed while waiting for selected dependencies"
        );
        ensure!(
            state.finalized_at.is_none(),
            "Replay finalized while API-origin dependencies were pending"
        );
        ensure!(
            !state.unrecorded_case_ids.contains(case_id)
                && !state.mysql.events.dirty_case_ids.contains(case_id)
                && !state.redis.case_has_runtime_failure(case_id)
                && !state.http_events.dirty_case_ids.contains(case_id),
            "API-origin case has failed dependency evidence; ownership was retained"
        );
        let now = Instant::now();
        ensure!(
            now < deadline,
            "API-origin absolute request budget expired; case ownership was retained"
        );
        let mut failed = false;
        let mut missing = false;
        tail.selected.retain(|selected| {
            let status = match selected {
                SelectedExchange::Redis(index) => state.redis.exchange_status(*index),
                SelectedExchange::Mysql(index) => state
                    .mysql
                    .exchanges
                    .get(*index)
                    .map(|exchange| exchange.status),
            };
            missing |= status.is_none();
            failed |= status == Some(ReplayExchangeStatus::Failed);
            status.is_none_or(|status| !status.is_consumed())
        });
        ensure!(
            !missing,
            "API-origin selected dependency disappeared from its replay inventory"
        );
        ensure!(
            !failed,
            "API-origin selected dependency failed; case ownership was retained"
        );
        let remaining = tail.selected.len();
        if remaining == 0 {
            return Ok(());
        }
        drop(state);
        tokio::time::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(now))).await;
    }
}

pub(super) fn end(state: &mut ReplayState, case_id: &str) {
    state.api_origin_tails.cases.remove(case_id);
}

#[cfg(test)]
mod tests;
