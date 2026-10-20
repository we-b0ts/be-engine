//! Wait for finite recorded dependency tails, without inventing Target calls.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use tokio::time::Instant;
use uuid::Uuid;

use super::super::{ReplayExchangeStatus, ReplaySource, ReplayState};
use std::sync::Arc;
use tokio::sync::Mutex;

const MAX_SELECTED_REFS: usize = 100_000;
const POLL_INTERVAL: Duration = Duration::from_millis(25);
mod metadata;
mod ownership;

#[derive(Debug, Default)]
pub(in crate::replay) struct CaseTails {
    cases: BTreeMap<String, Option<CaseTail>>,
    process_rules: Vec<crate::BackgroundDependencyRuleConfig>,
}

impl CaseTails {
    pub(in crate::replay) fn with_process_rules(
        process_rules: Vec<crate::BackgroundDependencyRuleConfig>,
    ) -> Self {
        Self {
            cases: BTreeMap::new(),
            process_rules,
        }
    }
}

#[derive(Debug, Clone)]
struct CaseTail {
    budget: Duration,
    deadline: Option<Instant>,
    selected: Vec<SelectedExchange>,
}

#[derive(Debug, Clone, Copy)]
enum ResolvedExchange {
    Redis(usize),
    Mysql(usize),
    Http(usize),
}

#[derive(Debug, Clone, Copy)]
struct SelectedExchange {
    exchange: ResolvedExchange,
    process_owned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
enum RecordedReference {
    Redis { connection_id: Uuid, sequence: u64 },
    Mysql { connection_id: Uuid, sequence: u64 },
    Http { exchange_id: Uuid },
}

/// Prepare immutable references before activation, without starting a Target
/// budget for a begin that may still lose concurrent case admission.
pub(in crate::replay) async fn prepare(
    state: &Arc<Mutex<ReplayState>>,
    case_id: &str,
) -> Result<()> {
    let (case_dir, process_rules) = {
        let state = state.lock().await;
        if state.dependency_tails.cases.contains_key(case_id) {
            return Ok(());
        }
        (
            state
                .cases
                .get(case_id)
                .context("dependency-tail observation has no replay case")?
                .dir
                .clone(),
            state.dependency_tails.process_rules.clone(),
        )
    };
    let metadata = metadata::load(&case_dir).await?;
    let process_owned = match &metadata {
        Some(metadata) if metadata.process_owned_exemptions => {
            let mut owned =
                ownership::prepare(&case_dir, case_id, &metadata.references, process_rules).await?;
            owned.retain(|reference| !metadata.strict_references.contains(reference));
            owned
        }
        _ => BTreeSet::new(),
    };
    let mut state = state.lock().await;
    if state.dependency_tails.cases.contains_key(case_id) {
        return Ok(());
    }
    let tail = metadata
        .map(|metadata| {
            let mut seen = BTreeSet::new();
            for reference in &metadata.references {
                ensure!(
                    seen.insert(reference),
                    "dependency-tail observation repeats a selected exchange reference"
                );
            }
            let selected = resolve(&state, case_id, &metadata.references, &process_owned)?;
            let budget = Duration::from_millis(metadata.request_timeout_ms);
            Ok::<_, anyhow::Error>(CaseTail {
                budget,
                deadline: None,
                selected,
            })
        })
        .transpose()?;
    state.dependency_tails.cases.insert(case_id.into(), tail);
    Ok(())
}

/// Linearize the monotonic anchor with active-case admission. A repeated begin
/// on an already active case cannot renew the same deadline.
pub(in crate::replay) fn activate(state: &mut ReplayState, case_id: &str) -> Result<()> {
    if let Some(Some(tail)) = state.dependency_tails.cases.get_mut(case_id)
        && tail.deadline.is_none()
    {
        tail.deadline = Some(
            Instant::now()
                .checked_add(tail.budget)
                .context("dependency-tail absolute request budget is out of range")?,
        );
    }
    Ok(())
}

pub(super) async fn deadline(state: &Arc<Mutex<ReplayState>>, case_id: &str) -> Option<Instant> {
    state
        .lock()
        .await
        .dependency_tails
        .cases
        .get(case_id)
        .and_then(Option::as_ref)
        .and_then(|tail| tail.deadline)
}

fn resolve(
    state: &ReplayState,
    case_id: &str,
    references: &[RecordedReference],
    process_owned: &BTreeSet<RecordedReference>,
) -> Result<Vec<SelectedExchange>> {
    let redis_keys = references
        .iter()
        .filter_map(|reference| match reference {
            RecordedReference::Redis {
                connection_id,
                sequence,
            } => Some((*connection_id, *sequence)),
            _ => None,
        })
        .collect();
    let redis = state
        .redis
        .case_wire_exchange_indices(case_id, &redis_keys)?;
    let mysql_keys: BTreeSet<_> = references
        .iter()
        .filter_map(|reference| match reference {
            RecordedReference::Mysql {
                connection_id,
                sequence,
            } => Some((*connection_id, *sequence)),
            _ => None,
        })
        .collect();
    let http_keys = references
        .iter()
        .filter_map(|reference| match reference {
            RecordedReference::Http { exchange_id } => Some(*exchange_id),
            _ => None,
        })
        .collect();
    let http = state.http_case_exchange_indices(case_id, &http_keys)?;
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
                "dependency-tail MySQL reference is ambiguous in its Case semantic dependencies"
            );
        }
    }
    ensure!(
        mysql.len() == mysql_keys.len(),
        "dependency-tail MySQL reference is absent from its Case semantic dependencies"
    );
    Ok(references
        .iter()
        .map(|reference| {
            let exchange = match reference {
                RecordedReference::Redis {
                    connection_id,
                    sequence,
                } => ResolvedExchange::Redis(redis[&(*connection_id, *sequence)]),
                RecordedReference::Mysql {
                    connection_id,
                    sequence,
                } => ResolvedExchange::Mysql(mysql[&(*connection_id, *sequence)]),
                RecordedReference::Http { exchange_id } => {
                    ResolvedExchange::Http(http[exchange_id])
                }
            };
            SelectedExchange {
                exchange,
                process_owned: process_owned.contains(reference),
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
        .dependency_tails
        .cases
        .get(case_id)
        .cloned()
        .flatten();
    let Some(mut tail) = tail else {
        return Ok(());
    };
    let deadline = tail
        .deadline
        .context("dependency-tail case budget was not activated")?;
    loop {
        let state = state.lock().await;
        ensure!(
            state.active_case_id.as_deref() == Some(case_id),
            "dependency-tail case ownership changed while waiting for selected dependencies"
        );
        ensure!(
            state.finalized_at.is_none(),
            "Replay finalized while dependency-tail dependencies were pending"
        );
        ensure!(
            !state.unrecorded_case_ids.contains(case_id)
                && !state.mysql.events.dirty_case_ids.contains(case_id)
                && !state.redis.case_has_runtime_failure(case_id)
                && !state.http_events.dirty_case_ids.contains(case_id),
            "dependency-tail case has failed dependency evidence; ownership was retained"
        );
        let now = Instant::now();
        ensure!(
            now < deadline,
            "dependency-tail absolute request budget expired; case ownership was retained"
        );
        let mut failed = false;
        let mut missing = false;
        let mut remaining = 0;
        tail.selected.retain(|selected| {
            let status = match selected.exchange {
                ResolvedExchange::Redis(index) => state.redis.exchange_status(index),
                ResolvedExchange::Mysql(index) => state
                    .mysql
                    .exchanges
                    .get(index)
                    .map(|exchange| exchange.status),
                ResolvedExchange::Http(index) => state.http_exchange_status(index),
            };
            missing |= status.is_none();
            failed |= status == Some(ReplayExchangeStatus::Failed);
            // Source-proven process work need not be started by Target for this
            // case. Once Target starts it, its real delivery/termination still
            // has to finish; exemption never manufactures consumption.
            let waits = status.is_none_or(|status| {
                !status.is_consumed()
                    && !(selected.process_owned && status == ReplayExchangeStatus::Available)
            });
            remaining += usize::from(waits);
            // Keep unused process entries observable while other obligations
            // remain: Target may begin one during this wait, and then its real
            // delivery must complete before releasing the case.
            status.is_none_or(|status| !status.is_consumed())
        });
        ensure!(
            !missing,
            "dependency-tail selected dependency disappeared from its replay inventory"
        );
        ensure!(
            !failed,
            "dependency-tail selected dependency failed; case ownership was retained"
        );
        if remaining == 0 {
            return Ok(());
        }
        drop(state);
        tokio::time::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(now))).await;
    }
}

pub(super) fn end(state: &mut ReplayState, case_id: &str) {
    state.dependency_tails.cases.remove(case_id);
}

#[cfg(test)]
mod tests;
