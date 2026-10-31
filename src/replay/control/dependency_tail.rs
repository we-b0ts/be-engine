//! Wait for finite recorded dependency tails, without inventing Target calls.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use uuid::Uuid;

use super::super::{ReplayExchangeStatus, ReplaySource, ReplayState};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;

const MAX_SELECTED_REFS: usize = 100_000;
const POLL_INTERVAL: Duration = Duration::from_millis(25);
pub(in crate::replay) const TARGET_STOP_CLEANUP_GRACE: Duration = Duration::from_secs(30);
mod metadata;
mod progress;
pub(in crate::replay) use metadata::load_cleanup_refs;

#[derive(Debug)]
pub(in crate::replay) struct CaseTails {
    cases: BTreeMap<String, Option<CaseTail>>,
    async_rules: BTreeMap<String, crate::policy::AsyncApiRules>,
    request_timeout: Duration,
    no_progress_timeout: Duration,
    waits: BTreeMap<String, serde_json::Value>,
    failures: BTreeMap<String, serde_json::Value>,
    source_business_incomplete: BTreeSet<String>,
}

impl Default for CaseTails {
    fn default() -> Self {
        Self {
            cases: BTreeMap::new(),
            async_rules: BTreeMap::new(),
            request_timeout: crate::replay::ReplayLifecycleConfig::default().request_timeout,
            no_progress_timeout: Duration::from_millis(
                crate::replay::DEFAULT_REPLAY_CASE_NO_PROGRESS_TIMEOUT_MS,
            ),
            waits: BTreeMap::new(),
            failures: BTreeMap::new(),
            source_business_incomplete: BTreeSet::new(),
        }
    }
}
impl CaseTails {
    pub(in crate::replay) fn target_stop_required(&self, case_id: &str) -> bool {
        self.cases
            .get(case_id)
            .and_then(Option::as_ref)
            .is_some_and(|tail| tail.source_stop_required)
    }
    pub(in crate::replay) fn with_async_rules(
        mut self,
        rules: BTreeMap<String, crate::policy::AsyncApiRules>,
        request_timeout: Duration,
    ) -> Self {
        self.async_rules = rules;
        self.request_timeout = request_timeout;
        self
    }

    pub(in crate::replay) fn with_no_progress_timeout(mut self, timeout: Duration) -> Self {
        self.no_progress_timeout = timeout;
        self
    }

    pub(in crate::replay) fn failure(&self, case: &str) -> Option<&serde_json::Value> {
        self.failures.get(case)
    }

    pub(in crate::replay) fn failures(&self) -> Vec<serde_json::Value> {
        self.failures.values().cloned().chain(self.source_business_incomplete.iter().map(|case|
            serde_json::json!({"kind":"source_business_incomplete","case_id":case,"requires_new_recording":true,"reason":"Source observation ended without its declared async completion resource"})
        )).collect()
    }

    pub(in crate::replay) fn waiting(&self, case: &str) -> Option<&serde_json::Value> {
        self.waits.get(case)
    }
}

#[derive(Debug, Clone)]
struct CaseTail {
    budget: Duration,
    interaction_post_input: Option<Duration>,
    deadline: Option<Instant>,
    selected: Vec<SelectedExchange>,
    source_stop_required: bool,
    source_stop_after: Option<Duration>,
    stop_prepared_at: Option<Instant>,
    failure_completion: bool,
    timeout_completion: bool,
    quiescing: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy)]
enum ResolvedExchange {
    Redis(usize),
    RedisRpcPush(usize),
    Mysql(usize),
    Http(usize),
    Connect(usize),
    Memcached(usize),
    Motan(usize),
    Kafka(crate::replay::kafka::FiniteExchange),
}

#[derive(Debug, Clone)]
struct SelectedExchange {
    reference: RecordedReference,
    exchange: ResolvedExchange,
    shared_initialization: bool,
    strict_reference: bool,
    lifecycle_cleanup: bool,
    lifecycle_gate: Option<Arc<AtomicBool>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::replay) enum RecordedReference {
    Redis { connection_id: Uuid, sequence: u64 },
    RedisRpcPush { connection_id: Uuid, sequence: u64 },
    Mysql { connection_id: Uuid, sequence: u64 },
    Http { exchange_id: Uuid },
    Connect { event_id: Uuid },
    Memcached { connection_id: Uuid, sequence: u64 },
    Motan { connection_id: Uuid, sequence: u64 },
    KafkaProduce { connection_id: Uuid, sequence: u64 },
    KafkaFetch { connection_id: Uuid, sequence: u64 },
    KafkaDelivery { connection_id: Uuid, sequence: u64 },
}

pub(in crate::replay) fn recorded_reference(
    event: &serde_json::Value,
) -> Result<Option<RecordedReference>> {
    metadata::reference(event)
}

pub(in crate::replay) fn references_consumed(
    state: &ReplayState,
    case: &str,
    references: &[RecordedReference],
) -> Result<bool> {
    Ok(resolve(state, case, references)?.iter().all(|selected| {
        exchange_status(state, selected.exchange).is_some_and(ReplayExchangeStatus::is_consumed)
    }))
}

/// Reuse existing ownership/omission authority without making unused business
/// exchanges optional merely to accelerate an input.
pub(in crate::replay) fn timing_optional(
    state: &ReplayState,
    case: &str,
    reference: RecordedReference,
) -> bool {
    state
        .dependency_tails
        .cases
        .get(case)
        .and_then(Option::as_ref)
        .and_then(|tail| tail.selected.iter().find(|s| s.reference == reference))
        .is_some_and(|selected| {
            selected.lifecycle_cleanup || permits_unstarted_omission(state, selected)
        })
}

fn exchange_status(
    state: &ReplayState,
    exchange: ResolvedExchange,
) -> Option<ReplayExchangeStatus> {
    match exchange {
        ResolvedExchange::Redis(index) => state.redis.exchange_status(index),
        ResolvedExchange::RedisRpcPush(index) => state.redis.pubsub.finite_rpc_push_status(index),
        ResolvedExchange::Mysql(index) => state
            .mysql
            .exchanges
            .get(index)
            .map(|exchange| exchange.status),
        ResolvedExchange::Http(index) => state.http_exchange_status(index),
        ResolvedExchange::Connect(index) => state.connect_failures.status(index),
        ResolvedExchange::Memcached(index) => state.memcached.finite_exchange_status(index),
        ResolvedExchange::Motan(index) => state.motan.finite_exchange_status(index),
        ResolvedExchange::Kafka(exchange) => state.kafka.finite_exchange_status(exchange),
    }
}

fn permits_unstarted_omission(state: &ReplayState, selected: &SelectedExchange) -> bool {
    if selected.strict_reference {
        return false;
    }
    match selected.exchange {
        ResolvedExchange::Mysql(index) => state.mysql.permits_unstarted_omission(index),
        ResolvedExchange::Http(index) => {
            selected.shared_initialization
                && state.http_exchange_status(index) == Some(ReplayExchangeStatus::Available)
        }
        _ => false,
    }
}

/// Prepare immutable references before activation, without starting a Target
/// budget for a begin that may still lose concurrent case admission.
pub(in crate::replay) async fn prepare(
    state: &Arc<Mutex<ReplayState>>,
    case_id: &str,
) -> Result<()> {
    let (case_dir, dependencies, async_rules, request_timeout) = {
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
            state
                .cases
                .get(case_id)
                .context("dependency-tail Case missing")?
                .dependencies_path
                .clone(),
            state.dependency_tails.async_rules.clone(),
            state.dependency_tails.request_timeout,
        )
    };
    let metadata =
        metadata::load_effective(&case_dir, &dependencies, &async_rules, request_timeout).await?;
    let http_completion = metadata::http_completion_rules(&case_dir, &async_rules).await?;
    let mut state = state.lock().await;
    if state.dependency_tails.cases.contains_key(case_id) {
        return Ok(());
    }
    if metadata
        .as_ref()
        .is_some_and(|metadata| !metadata.business_complete)
    {
        state
            .dependency_tails
            .source_business_incomplete
            .insert(case_id.to_owned());
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
            let mut selected = resolve(&state, case_id, &metadata.references)?;
            for (selected, reference) in selected.iter_mut().zip(&metadata.references) {
                selected.strict_reference = metadata.strict_references.contains(reference);
                selected.shared_initialization = match selected.exchange {
                    ResolvedExchange::Http(index) => {
                        state.http_shared_initialization(index, &http_completion)
                    }
                    _ => false,
                };
                selected.lifecycle_cleanup = metadata.cleanup_refs.contains(reference);
                selected.lifecycle_gate = selected
                    .lifecycle_cleanup
                    .then(|| Arc::new(AtomicBool::new(false)));
            }
            let budget = Duration::from_millis(metadata.request_timeout_ms);
            Ok::<_, anyhow::Error>(CaseTail {
                budget,
                interaction_post_input: metadata
                    .interaction_post_input_ms
                    .map(Duration::from_millis),
                deadline: None,
                selected,
                source_stop_required: metadata.source_stop_required,
                source_stop_after: metadata.source_stop_after_ms.map(Duration::from_millis),
                stop_prepared_at: None,
                failure_completion: metadata.failure_completion,
                timeout_completion: metadata.timeout_completion,
                quiescing: Arc::new(AtomicBool::new(false)),
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

pub(in crate::replay) async fn deadline(
    state: &Arc<Mutex<ReplayState>>,
    case_id: &str,
) -> Option<Instant> {
    let state = state.lock().await;
    state.case_cleanup.deadline(case_id).or_else(|| {
        state
            .dependency_tails
            .cases
            .get(case_id)
            .and_then(Option::as_ref)
            .and_then(|tail| tail.deadline)
    })
}

/// The caller keeps this Case active while stopping the corresponding Target.
pub(super) async fn target_stop_required(state: &Arc<Mutex<ReplayState>>, case_id: &str) -> bool {
    state
        .lock()
        .await
        .dependency_tails
        .cases
        .get(case_id)
        .and_then(Option::as_ref)
        .is_some_and(|tail| tail.source_stop_required)
}

/// Target stop and accepted I/O finalization share one engine cleanup budget.
/// Repeated commands cannot move this boundary forward.
pub(super) async fn cleanup_deadline(
    state: &Arc<Mutex<ReplayState>>,
    case_id: &str,
) -> Option<Instant> {
    let state = state.lock().await;
    state.case_cleanup.deadline(case_id).or_else(|| {
        state
            .dependency_tails
            .cases
            .get(case_id)
            .and_then(Option::as_ref)
            .and_then(|tail| {
                tail.stop_prepared_at
                    .map(|at| at + TARGET_STOP_CLEANUP_GRACE)
                    .or(tail.deadline)
            })
    })
}

impl ReplayState {
    /// The same delivered failure can make Target close its worker naturally
    /// before the controller's next poll. Accept only the complete ready scope;
    /// admission and the final process-stop receipt remain unchanged.
    pub(in crate::replay) fn arm_failure_cleanup_if_ready(&self, case: &str) -> bool {
        if self.failure_cleanup_readiness(case) != Some(true) {
            return false;
        }
        let tail = self
            .dependency_tails
            .cases
            .get(case)
            .and_then(Option::as_ref)
            .expect("checked failure scope");
        for selected in &tail.selected {
            if let Some(gate) = &selected.lifecycle_gate {
                gate.store(true, Ordering::Release);
            }
        }
        tail.quiescing.store(true, Ordering::Release);
        true
    }

    pub(in crate::replay) fn async_failure_delivery_pending(&self, case: &str) -> bool {
        self.failure_cleanup_readiness(case) == Some(false)
    }

    pub(in crate::replay) fn async_case_quiescing(&self) -> bool {
        self.active_case_id
            .as_deref()
            .and_then(|case| self.dependency_tails.cases.get(case))
            .and_then(Option::as_ref)
            .is_some_and(|tail| tail.quiescing.load(Ordering::Acquire))
    }

    /// None means the scope is incomplete/dirty; false only waits for an
    /// already started ordinary delivery transaction to publish its result.
    fn failure_cleanup_readiness(&self, case: &str) -> Option<bool> {
        let Some(Some(tail)) = self.dependency_tails.cases.get(case) else {
            return None;
        };
        if !tail.source_stop_required
            || !tail.failure_completion
            || self.active_case_id.as_deref() != Some(case)
            || self.finalized_at.is_some()
            || self.unrecorded_case_ids.contains(case)
            || self.mysql.events.dirty_case_ids.contains(case)
            || self.redis.case_has_runtime_failure(case)
            || self.http_events.case_has_runtime_failure(case)
            || !tail
                .selected
                .iter()
                .any(|selected| selected.lifecycle_cleanup)
        {
            return None;
        }
        let mut pending = false;
        for selected in &tail.selected {
            if selected.shared_initialization && permits_unstarted_omission(self, selected) {
                continue;
            }
            match exchange_status(self, selected.exchange)? {
                ReplayExchangeStatus::Consumed => (),
                ReplayExchangeStatus::AwaitingClientTermination if selected.lifecycle_cleanup => (),
                ReplayExchangeStatus::Responding if !selected.lifecycle_cleanup => pending = true,
                _ => return None,
            }
        }
        Some(!pending)
    }

    pub(in crate::replay) fn async_cleanup_gate(
        &self,
        case: &str,
        reference: RecordedReference,
    ) -> Option<Arc<AtomicBool>> {
        self.dependency_tails
            .cases
            .get(case)
            .and_then(Option::as_ref)?
            .selected
            .iter()
            .find(|selected| selected.reference == reference)?
            .lifecycle_gate
            .clone()
    }

    pub(in crate::replay) fn async_cleanup_deadline(&self, case: &str) -> Option<Instant> {
        self.dependency_tails
            .cases
            .get(case)
            .and_then(Option::as_ref)
            .and_then(|tail| {
                tail.stop_prepared_at
                    .map(|at| at + TARGET_STOP_CLEANUP_GRACE)
            })
    }
}

fn resolve(
    state: &ReplayState,
    case_id: &str,
    references: &[RecordedReference],
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
    let rpc_pushes = state.redis.pubsub.finite_rpc_pushes(case_id)?;
    let memcached = state.memcached.finite_exchanges(case_id)?;
    let motan = state.motan.finite_exchanges(case_id)?;
    let kafka = state.kafka.finite_exchanges(case_id)?;
    references
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
                RecordedReference::RedisRpcPush {
                    connection_id,
                    sequence,
                } => ResolvedExchange::RedisRpcPush(
                    *rpc_pushes
                        .get(&(*connection_id, *sequence))
                        .context("finite Redis callback reference is absent from Case inventory")?,
                ),
                RecordedReference::Http { exchange_id } => {
                    ResolvedExchange::Http(http[exchange_id])
                }
                RecordedReference::Connect { event_id } => {
                    ResolvedExchange::Connect(state.connect_failures.resolve(case_id, *event_id)?)
                }
                RecordedReference::Memcached {
                    connection_id,
                    sequence,
                } => ResolvedExchange::Memcached(
                    *memcached
                        .get(&(*connection_id, *sequence))
                        .context("finite Memcached reference absent from Case inventory")?,
                ),
                RecordedReference::Motan {
                    connection_id,
                    sequence,
                } => ResolvedExchange::Motan(
                    *motan
                        .get(&(*connection_id, *sequence))
                        .context("finite Motan reference absent from Case inventory")?,
                ),
                RecordedReference::KafkaProduce {
                    connection_id,
                    sequence,
                } => ResolvedExchange::Kafka(
                    *kafka
                        .get(&("produce", *connection_id, *sequence))
                        .context("finite Kafka reference absent from Case inventory")?,
                ),
                RecordedReference::KafkaFetch {
                    connection_id,
                    sequence,
                } => ResolvedExchange::Kafka(
                    *kafka
                        .get(&("fetch", *connection_id, *sequence))
                        .context("finite Kafka reference absent from Case inventory")?,
                ),
                RecordedReference::KafkaDelivery {
                    connection_id,
                    sequence,
                } => ResolvedExchange::Kafka(
                    *kafka
                        .get(&("delivery", *connection_id, *sequence))
                        .context("finite Kafka reference absent from Case inventory")?,
                ),
            };
            Ok(SelectedExchange {
                reference: *reference,
                exchange,
                shared_initialization: false,
                strict_reference: false,
                lifecycle_cleanup: false,
                lifecycle_gate: None,
            })
        })
        .collect()
}

/// Normal completion requires real consumption. Failed requests preserve
/// unstarted entries as unused and drain only their actual accepted I/O.
pub(super) async fn drain(state: &Arc<Mutex<ReplayState>>, case_id: &str) -> Result<()> {
    drain_selected(state, case_id, false).await
}

/// Already claimed client-terminated I/O must see Target stop before it can
/// complete. Ordinary finite resources must be consumed before requesting stop.
pub(super) async fn prepare_target_stop(
    state: &Arc<Mutex<ReplayState>>,
    case_id: &str,
) -> Result<()> {
    drain_selected(state, case_id, true).await
}

/// A native peer close cannot certify application teardown after a Replay
/// rejection. Its hook may still sleep even when accepted I/O has drained.
/// The caller also checks this under the final ownership-release lock so a
/// rejection between tail drain and release cannot admit the next Case.
pub(super) fn ensure_interaction_not_failed(state: &ReplayState, case_id: &str) -> Result<()> {
    let native = state
        .dependency_tails
        .cases
        .get(case_id)
        .and_then(Option::as_ref)
        .is_some_and(|tail| tail.interaction_post_input.is_some());
    ensure!(
        !native
            || !(state.case_cleanup.deadline(case_id).is_some()
                || super::case_execution::failed(state, case_id)),
        "interaction dependency execution failed; case ownership was retained for Target shutdown"
    );
    Ok(())
}

async fn drain_selected(
    state: &Arc<Mutex<ReplayState>>,
    case_id: &str,
    before_target_stop: bool,
) -> Result<()> {
    let shared = state;
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
    ensure!(
        !before_target_stop || tail.source_stop_required,
        "this Source Case has no Target-stop lifecycle boundary"
    );
    let request_deadline = tail
        .deadline
        .context("dependency-tail case budget was not activated")?;
    let mut deadline = if before_target_stop {
        request_deadline
    } else {
        tail.stop_prepared_at
            .map(|at| at + TARGET_STOP_CLEANUP_GRACE)
            .unwrap_or(request_deadline)
    };
    let stop_at = tail
        .source_stop_after
        .filter(|_| tail.timeout_completion)
        .and_then(|offset| {
            request_deadline
                .checked_sub(tail.budget)?
                .checked_add(offset)
        });
    let idle_budget = shared.lock().await.dependency_tails.no_progress_timeout;
    let mut progress = progress::NoProgress::new(
        idle_budget.saturating_add(tail.interaction_post_input.unwrap_or_default()),
    );
    loop {
        let mut state = state.lock().await;
        ensure!(
            state.active_case_id.as_deref() == Some(case_id),
            "dependency-tail case ownership changed while waiting for selected dependencies"
        );
        ensure!(
            state.finalized_at.is_none(),
            "Replay finalized while dependency-tail dependencies were pending"
        );
        if state.unrecorded_case_ids.contains(case_id)
            || state.mysql.events.dirty_case_ids.contains(case_id)
            || state.redis.case_has_runtime_failure(case_id)
            || state.http_events.case_has_runtime_failure(case_id)
        {
            super::case_cleanup::mark_failed(&mut state, case_id)?;
        }
        ensure_interaction_not_failed(&state, case_id)?;
        let failure_cleanup = state.case_cleanup.deadline(case_id).is_some();
        if let Some(cleanup) = state.case_cleanup.deadline(case_id) {
            deadline = cleanup;
        }
        if failure_cleanup && !before_target_stop {
            drop(state);
            return super::case_cleanup::drain_started(shared, case_id, Some(deadline)).await;
        }
        let now = Instant::now();
        if !before_target_stop {
            ensure!(
                now < deadline,
                "{}; case ownership was retained",
                if tail.stop_prepared_at.is_some() {
                    "dependency-tail cleanup budget expired"
                } else {
                    "dependency-tail absolute request budget expired"
                }
            );
        }
        let mut failed = false;
        let mut missing = false;
        let mut remaining = 0;
        tail.selected.retain(|selected| {
            let status = exchange_status(&state, selected.exchange);
            missing |= status.is_none();
            failed |= status == Some(ReplayExchangeStatus::Failed);
            // Source-proven process work need not be started by Target for this
            // case. Once Target starts it, its real delivery/termination still
            // has to finish; exemption never manufactures consumption.
            let waits = status.is_none_or(|status| {
                !(status.is_consumed()
                    || before_target_stop
                        && selected.lifecycle_cleanup
                        && status == ReplayExchangeStatus::AwaitingClientTermination)
                    && !permits_unstarted_omission(&state, selected)
                    && !(failure_cleanup
                        && matches!(
                            status,
                            ReplayExchangeStatus::Available | ReplayExchangeStatus::Failed
                        ))
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
        if failed && !failure_cleanup {
            super::case_cleanup::mark_failed(&mut state, case_id)?;
            drop(state);
            continue;
        }
        if remaining == 0 {
            if before_target_stop {
                if !failure_cleanup
                    && let Some(stop_at) = stop_at
                    && now < stop_at
                {
                    drop(state);
                    tokio::time::sleep(POLL_INTERVAL.min(stop_at.saturating_duration_since(now)))
                        .await;
                    continue;
                }
                state.target_stop_prepared.insert(case_id.into());
                for selected in &tail.selected {
                    if let Some(gate) = &selected.lifecycle_gate {
                        gate.store(true, Ordering::Release);
                    }
                }
                if let Some(Some(original)) = state.dependency_tails.cases.get_mut(case_id) {
                    original.stop_prepared_at.get_or_insert(now);
                    original.quiescing.store(true, Ordering::Release);
                }
            }
            return Ok(());
        }
        let in_flight = super::case_cleanup::has_started(&state);
        let expired = progress.observe(now, in_flight, progress::counts(&state, case_id));
        let waiting = progress::waiting(&tail, &state, &progress, now, remaining, in_flight);
        state
            .dependency_tails
            .waits
            .insert(case_id.into(), waiting.clone());
        if expired && !failure_cleanup {
            let failure = serde_json::json!({
                "kind":"case_no_progress", "case_id":case_id,
                "reason":progress.failure_reason(remaining),
                "waiting":waiting
            });
            state
                .dependency_tails
                .failures
                .insert(case_id.into(), failure);
            if tail.interaction_post_input.is_some() {
                // Wire close did not prove the application hook finished.
                // Keep the failed Case active so ordinary runner cleanup stops
                // Target instead of attributing its late calls to the next Case.
                anyhow::bail!(
                    "{}; interaction case ownership was retained",
                    progress.failure_reason(remaining)
                );
            }
            super::case_cleanup::mark_failed(&mut state, case_id)?;
            drop(state);
            continue;
        }
        ensure!(
            now < deadline,
            "dependency-tail absolute request budget expired; case ownership was retained"
        );
        drop(state);
        tokio::time::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(now))).await;
    }
}

pub(super) fn end(state: &mut ReplayState, case_id: &str) {
    state.dependency_tails.waits.remove(case_id);
    state.dependency_tails.cases.remove(case_id);
}

#[cfg(test)]
mod async_tests;
#[cfg(test)]
mod interaction_tests;
#[cfg(test)]
mod no_progress_tests;
#[cfg(test)]
mod tests;
