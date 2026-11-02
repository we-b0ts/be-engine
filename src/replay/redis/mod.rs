use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::DependencyExchangeOutcome;
use crate::config::process_owned_dependencies::redis_rule_matches;
use crate::redis::{
    BufferedReader as RedisBufferedReader, RedisCommand, RedisFrameKind,
    frame_kind as redis_frame_kind, is_pubsub_command, read_frame as read_redis_frame,
    redis_command, validate_subscription_confirmation,
};

use super::{
    CaseExchangeIndex, ReplayExchangeStatus, ReplayExchangeTiming, ReplayProtocol, ReplaySource,
    ReplayState, ReplayTarget, SuccessDetailBudget, TargetKey, normalize_host, push_success_detail,
    register_replay_target,
};

mod builtins;
mod connection_scope;
mod request_identity;
pub(crate) use request_identity::request_fingerprint;
pub(in crate::replay) mod cross_case;
use crate::replay::json_order as json;
pub(in crate::replay) use cross_case::load as load_cross_case;
pub(in crate::replay) mod activity;
mod api_origin;
pub(in crate::replay) mod append;
pub(in crate::replay) mod candidates;
mod case_scope;
pub(crate) mod expiration;
#[cfg(test)]
mod field_identity_tests;
mod key_access;
pub(in crate::replay) mod key_selector;
#[cfg(test)]
mod lane_tests;
mod matching;
mod native_source;
pub(in crate::replay) mod observations;
mod process_owned;
pub(in crate::replay) mod pubsub;
#[cfg(test)]
mod read_back_tests;
pub(in crate::replay) mod read_commutation;
mod report_inventory;
mod request_order;
pub(crate) mod shared_read;
mod snapshot_seed;
mod startup;
pub(crate) mod value;
use connection_scope::{ConnectionScopes, TargetConnection};
use matching::redis_authentication_hint;
pub(super) mod snapshot_overlay;
use super::command_matching::{CaseConnectionBinding, is_process_lane};
use super::report::command::{
    CommandMatchedReport, CommandProtocolReport, CommandRequestReport, CommandUnusedReport,
};
use builtins::{redis_builtin, redis_is_builtin, redis_is_unsupported};
mod admission;
mod cleanup;
mod completion;
mod delivery;
mod evidence;
mod input_timing;
mod lifecycle;
use super::admission::{
    Barrier, Claim, ClaimKind, ClaimTicket, Finish, Lifecycle, NativeClaimKind,
};
use delivery::deliver_redis_exchange;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedConnection {
    target_host: String,
    target_port: u16,
    replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct RecordedExchange {
    #[serde(skip)]
    lifecycle_cleanup: bool,
    // Subscription aliases retain event identity without changing existing
    // Redis rule/evidence fingerprints, which serialize this projection.
    #[serde(default, skip_serializing)]
    id: Option<Uuid>,
    #[serde(default)]
    timestamp: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_started_at: Option<chrono::DateTime<chrono::Utc>>,
    connection_id: Uuid,
    sequence: u64,
    target_host: String,
    target_port: u16,
    resp_version: u8,
    database: i64,
    username: Option<String>,
    command: String,
    args: Vec<RecordedCapture>,
    response_kind: String,
    response: RecordedCapture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rpc_callback_capture: Option<String>,
    #[serde(default)]
    outcome: DependencyExchangeOutcome,
    #[serde(default)]
    duration_ms: u64,
    replay_safe: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    parse_warnings: Vec<String>,
    #[serde(default)]
    cache_snapshot_rule: Option<String>,
    #[serde(default)]
    cache_snapshot_hit: bool,
    #[serde(default)]
    session_setup: bool,
    #[serde(default)]
    capture: Option<crate::dependency::observation::CaptureMetadata>,
}

impl RecordedExchange {
    fn started_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.request_started_at.or_else(|| {
            self.timestamp?
                .checked_sub_signed(chrono::TimeDelta::milliseconds(
                    i64::try_from(self.duration_ms).ok()?,
                ))
        })
    }

    /// A floor-millisecond duration only establishes a conservative lower bound.
    fn earliest_start(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.request_started_at.or_else(|| {
            self.timestamp?
                .checked_sub_signed(chrono::TimeDelta::milliseconds(
                    i64::try_from(self.duration_ms.checked_add(1)?).ok()?,
                ))
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RecordedCapture {
    encoding: String,
    data: String,
    #[serde(default)]
    truncated: bool,
}

#[derive(Debug, Clone)]
struct ReplayExchange {
    claim: Option<ClaimTicket>,
    observation_rule: Option<String>,
    read_commutation_rule: Option<String>,
    subscription_alias: bool,
    response_evidence: Option<crate::dependency_index::RecordRef>,
    rpc_push: Option<usize>,
    shared_rule_id: Option<String>,
    source: ReplaySource,
    case_id: Option<String>,
    record: RecordedExchange,
    args: Vec<Vec<u8>>,
    response: Vec<u8>,
    status: ReplayExchangeStatus,
    timing: ReplayExchangeTiming,
    connection_independent: bool,
    reusable_snapshot: bool,
    matched_once: bool,
}

#[derive(Debug, Clone)]
struct MatchedRedisExchange {
    claim: Claim,
    refresh: Option<activity::Prepared>,
    observation: Option<observations::Prepared>,
    append: Option<append::PreparedAppend>,
    read_back: Option<super::policy::request_contract::PreparedReadBack>,
    time_read: Option<super::policy::request_contract::PreparedRedisTimeRead>,
    time_write: Option<super::policy::request_contract::PreparedRedisTimeWrite>,
    unified_delivery: Option<super::policy::request_contract::PreparedRedisDelivery>,
    rpc_push: Option<usize>,
    rpc_response: Option<Vec<u8>>,
    publish_duration_ms: u64,
    adapter_echo: Option<pubsub::echo::Prepared>,
    index: usize,
    connection_id: Uuid,
    response: Vec<u8>,
    timing: ReplayExchangeTiming,
    requires_binding: bool,
    report: CommandMatchedReport,
    rule_ids: Vec<String>,
}

#[derive(Debug, Default)]
pub(super) struct RedisReplayState {
    pub(in crate::replay) run_value_scopes: BTreeMap<Uuid, Arc<str>>,
    lifecycle: Lifecycle,
    timing_deliveries: input_timing::Deliveries,
    activity_refresh: activity::ActivityRefreshes,
    pub(super) shared_source_directories: BTreeMap<String, PathBuf>,
    observations: observations::Observations,
    read_commutation: read_commutation::ReadCommutation,
    append_streams: append::AppendStreams,
    request_event_index: Option<usize>,
    request_observed_at: Option<chrono::DateTime<chrono::Utc>>,
    request_observation_id: Option<uuid::Uuid>,
    request_observation_retained: bool,
    pub(in crate::replay) target_observations:
        Option<crate::replay::target_observation::TargetObservations>,
    pub(in crate::replay) pubsub: pubsub::PubSubState,
    pub(super) request_contracts: super::policy::request_contract::RequestContracts,
    pub(super) dynamic_values: super::policy::dynamic_values::DynamicValues,
    connection_scopes: ConnectionScopes,
    unordered_value: value::evidence::OrderEvidence,
    exchanges: Vec<ReplayExchange>,
    case_exchange_index: CaseExchangeIndex,
    pub(in crate::replay) candidates: candidates::Candidates,
    pub(super) events: RedisReplayEvents,
    snapshot_overlays: Vec<super::report::command::CommandSnapshotOverlayReport>,
    snapshot_overlay_warnings: Vec<String>,
}

impl RedisReplayState {
    pub(in crate::replay) fn with_run_value_scopes(scopes: BTreeMap<Uuid, Arc<str>>) -> Self {
        Self {
            run_value_scopes: scopes,
            ..Default::default()
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct RedisReplayEvents {
    request_order: request_order::RequestOrder,
    global_report: crate::replay::report::global_evidence::regular_usage::Usage,
    dirty_case_ids: BTreeSet<String>,
    pub(super) connections: usize,
    matched_count: usize,
    matched: Vec<CommandMatchedReport>,
    pub(in crate::replay) matched_details: SuccessDetailBudget,
    pub(super) unmatched: Vec<CommandRequestReport>,
    pub(super) unsupported: Vec<CommandRequestReport>,
    pub(super) unsafe_events: Vec<CommandRequestReport>,
}

impl RedisReplayState {
    pub(in crate::replay) fn prepare_candidates(&mut self) {
        self.candidates.register(&self.exchanges);
    }

    pub(in crate::replay) fn prepared_case_members(&self, case: &str) -> Arc<[usize]> {
        self.candidates.case_members(case)
    }

    pub(in crate::replay) fn case_wire_exchange_indices(
        &self,
        case_id: &str,
        selected: &BTreeSet<(Uuid, u64)>,
    ) -> Result<BTreeMap<(Uuid, u64), usize>> {
        let mut indices = BTreeMap::new();
        for (index, exchange) in self.exchanges.iter().enumerate() {
            let key = (exchange.record.connection_id, exchange.record.sequence);
            if exchange.source == ReplaySource::Case
                && exchange.case_id.as_deref() == Some(case_id)
                && selected.contains(&key)
            {
                ensure!(
                    indices.insert(key, index).is_none(),
                    "dependency-tail Redis reference is ambiguous in its Case semantic dependencies"
                );
            }
        }
        ensure!(
            indices.len() == selected.len(),
            "dependency-tail Redis reference is absent from its Case semantic dependencies"
        );
        Ok(indices)
    }

    pub(in crate::replay) fn exchange_status(&self, index: usize) -> Option<ReplayExchangeStatus> {
        self.exchanges
            .get(index)
            .map(|exchange| self.lifecycle.live_status(index, exchange.status))
    }

    pub(in crate::replay) fn case_has_runtime_failure(&self, case_id: &str) -> bool {
        self.events.dirty_case_ids.contains(case_id)
    }

    pub(in crate::replay) fn has_case_in_flight(&self) -> bool {
        self.observations.has_in_flight()
            || self.pubsub.has_case_delivery()
            || self.activity_refresh.has_in_flight()
            || self.exchanges.iter().enumerate().any(|(index, e)| {
                e.source == ReplaySource::Case
                    && !self.append_streams.idle_source(index)
                    && matches!(
                        self.lifecycle.live_status(index, e.status),
                        ReplayExchangeStatus::Responding
                            | ReplayExchangeStatus::AwaitingClientTermination
                    )
            })
    }

    pub(in crate::replay) fn has_in_flight(&self) -> bool {
        self.observations.has_in_flight()
            || self.pubsub.has_case_delivery()
            || self.activity_refresh.has_in_flight()
            || self.exchanges.iter().enumerate().any(|(index, e)| {
                !self.append_streams.idle_source(index)
                    && matches!(
                        self.lifecycle.live_status(index, e.status),
                        ReplayExchangeStatus::Responding
                            | ReplayExchangeStatus::AwaitingClientTermination
                    )
            })
    }

    pub(in crate::replay) fn validate_pubsub(&self) -> Result<()> {
        self.pubsub.validate_subscriptions(&self.exchanges)
    }
    pub(super) fn register_connection(
        &mut self,
        record: RecordedConnection,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        if !record.replay_safe {
            return Err(anyhow!(
                "unsafe Redis connection metadata for {}:{}",
                record.target_host,
                record.target_port
            ));
        }
        register_target(
            targets,
            &record.target_host,
            record.target_port,
            ReplayProtocol::Redis,
        )
    }

    pub(super) fn reject_proxy_error(record: &super::RecordedProxyError) -> Result<()> {
        if record.protocol == "redis" {
            return Err(anyhow!(
                "unsafe {} dependency proxy error: {}",
                record.protocol,
                record.error
            ));
        }
        Ok(())
    }

    pub(super) fn register_exchange(
        &mut self,
        record: RecordedExchange,
        source: ReplaySource,
        case_id: Option<&str>,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
        process_owned_dependencies: &[crate::BackgroundDependencyRuleConfig],
    ) -> Result<()> {
        ensure!(
            source != ReplaySource::Case
                || case_id.is_none_or(|case| !self.append_streams.has_case(case)),
            "cannot extend a prepared append stream Case inventory"
        );
        self.read_commutation.check_case_addition(source, case_id)?;
        self.observations.check_case_addition(source, case_id)?;
        self.activity_refresh.check_case_addition(source, case_id)?;
        record.outcome.validate()?;
        ensure!(
            record
                .outcome
                .termination()
                .is_none_or(|end| end.scope != crate::dependency::TerminationScope::Stream),
            "Redis termination must describe a TCP connection direction"
        );
        validate_recorded_exchange(
            "redis_exchange",
            &record.command,
            record.replay_safe || record.lifecycle_cleanup,
            record.response.truncated || record.args.iter().any(|capture| capture.truncated),
        )?;
        let args = record
            .args
            .iter()
            .map(RecordedCapture::decode)
            .collect::<Result<Vec<_>>>()?;
        self.append_streams
            .check_inventory_addition(&record, &args, source, case_id)?;
        self.read_commutation
            .check_inventory_addition(&record, &args, source, case_id)?;
        let response = record.response.decode()?;
        ensure!(
            record
                .outcome
                .termination()
                .is_none_or(|end| end.side != crate::dependency::TerminationSide::Client)
                || response.is_empty(),
            "Redis client termination response prefix has no recorded delivery timing"
        );
        validate_subscription_exchange(&record, &args, &response)?;
        let timing = ReplayExchangeTiming::from_recorded(record.duration_ms, record.outcome);
        let reusable_snapshot =
            snapshot_seed::validate(&record, source, process_owned_dependencies, &args)?;
        self.observations.check_inventory_addition(
            &record,
            &args,
            source,
            case_id,
            reusable_snapshot,
        )?;
        self.activity_refresh
            .check_inventory_addition(&record, &args, source, case_id)?;
        let connection_independent = is_process_lane(source)
            || (source.is_run_owned()
                && record.run_owner_kind() == Some("startup")
                && process_owned_dependencies.iter().any(|rule| {
                    redis_rule_matches(rule, record.target_port, &record.command, &args)
                }));
        register_target(
            targets,
            &record.target_host,
            record.target_port,
            ReplayProtocol::Redis,
        )?;
        // Central ledgers retain successful protocol controls as observations.
        // Builtins still own Target session context; these observations cannot
        // add finite slots or bind otherwise ordinary data lanes to a socket.
        let control_observation = record
            .capture
            .as_ref()
            .is_some_and(|capture| !capture.semantic_required)
            && !record.lifecycle_cleanup
            && record.replay_safe
            && record.response_kind != "error"
            && redis_is_builtin(&record.command.to_ascii_uppercase())
            && (record.session_setup
                || record.command.eq_ignore_ascii_case("PING")
                || record.command.eq_ignore_ascii_case("QUIT"));
        // Rejected SDK identity announcements are observations as well. Other
        // recorded session errors and termination keep their native witnesses.
        if record.outcome == DependencyExchangeOutcome::Response
            && (control_observation || crate::redis::is_client_library_info(&record.command, &args))
        {
            return Ok(());
        }
        self.connection_scopes
            .register(&record, &args, source, case_id);
        let exchange_index = self.exchanges.len();
        self.case_exchange_index
            .register(source, case_id, exchange_index);
        let rpc_push = self.pubsub.link(&record, source, case_id, &args)?;
        self.exchanges.push(ReplayExchange {
            claim: None,
            observation_rule: None,
            read_commutation_rule: None,
            subscription_alias: false,
            response_evidence: None,
            rpc_push,
            shared_rule_id: None,
            source,
            case_id: case_id.map(ToOwned::to_owned),
            record,
            args,
            response,
            status: ReplayExchangeStatus::Available,
            timing,
            connection_independent,
            reusable_snapshot,
            matched_once: false,
        });
        Ok(())
    }

    pub(super) fn snapshot(&self) -> CommandProtocolReport {
        CommandProtocolReport {
            target_event_index_scope: Some("case_request_admission"),
            append_streams: self.append_streams.reports(),
            append_streams_omitted: self.append_streams.omitted(),
            state_observations: self.observations.reports(),
            state_observations_omitted: self.observations.omitted(),
            activity_refreshes: self.activity_refresh.reports(),
            activity_refreshes_omitted: self.activity_refresh.omitted(),
            pubsub: self.pubsub.report(),
            unordered_value: Some(self.unordered_value.clone()),
            connections: self.events.connections,
            matched_count: self.events.matched_count,
            matched: self.events.matched.clone(),
            unmatched: self.events.unmatched.clone(),
            unsupported: self.events.unsupported.clone(),
            unsafe_events: self
                .events
                .unsafe_events
                .iter()
                .cloned()
                .chain(self.initial_expiry_violations())
                .collect(),
            unused_case: unused(&self.exchanges, ReplaySource::Case)
                .into_iter()
                .chain(self.pubsub.unused(ReplaySource::Case))
                .collect(),
            unused_global_count: Some(self.global_unused_count()),
            unused_global: unused(&self.exchanges, ReplaySource::Startup)
                .into_iter()
                .chain(self.pubsub.unused(ReplaySource::Startup))
                .take(100)
                .collect(),
            snapshot_overlays: self.snapshot_overlays.clone(),
            warnings: self.snapshot_overlay_warnings.clone(),
        }
    }

    pub(super) fn case_is_dirty(&self, case_id: &str) -> bool {
        self.pubsub.case_is_dirty(case_id)
            || self.unsettled_initial_expiry(case_id)
            || self.events.dirty_case_ids.contains(case_id)
            || self.case_exchange_index.any(case_id, |index| {
                self.exchanges.get(index).is_some_and(|exchange| {
                    if exchange.source != ReplaySource::Case {
                        return false;
                    }
                    if exchange.reusable_snapshot {
                        !exchange.matched_once
                    } else {
                        !exchange.status.is_consumed()
                    }
                })
            })
    }
}

pub(super) async fn handle_connection(
    stream: TcpStream,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
) -> Result<()> {
    let client_id = Uuid::new_v4();
    let result = serve_connection(stream, target, state.clone(), client_id).await;
    state.lock().await.redis.finish_pubsub_client(client_id);
    result
}

async fn serve_connection(
    mut stream: TcpStream,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    client_id: Uuid,
) -> Result<()> {
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    state.lock().await.redis.events.connections += 1;
    let control = crate::dependency::termination::ConnectionControl::new(&stream)?;
    let mut reader = RedisBufferedReader::new(&mut stream, 64 * 1024 * 1024);
    let mut resp_version = 2_u8;
    let mut database = 0_i64;
    let mut username: Option<String> = None;
    let mut connection_binding = CaseConnectionBinding::default();
    let (push_tx, mut push_rx) = tokio::sync::mpsc::channel::<pubsub::Delivery>(256);
    loop {
        let read = tokio::select! {
            frame = read_redis_frame(&mut reader) => frame,
            Some(delivery) = push_rx.recv() => {
                let _callback_guard=delivery.matched.as_ref().and_then(|matched|match &matched.claim {
                    Claim::Finite(ticket)=>Some(ticket.guard()),
                    Claim::Native(_)=>None,
                });
                let mut replay = state.lock().await;
                if !delivery.case_is_current(&replay) || replay.finalized_at.is_some()
                    || !replay.redis.pubsub.is_subscribed(client_id, delivery.push) {
                    replay.redis.fail_pubsub_input(delivery.push,delivery.case_id.as_deref(),"Pub/Sub input Case or subscription already ended");
                    if let Some(m) = &delivery.matched { replay.redis.fail_exchange(m, "callback case already ended".into()); }
                    continue;
                }
                let timing_scope = input_timing::scope(&replay);
                drop(replay);
                let sent = tokio::time::timeout(std::time::Duration::from_secs(5), reader.inner.write_all(&delivery.bytes)).await;
                let mut replay = state.lock().await;
                let sent = sent.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Pub/Sub push delivery timed out")).and_then(|r| r);
                match sent {
                    Ok(()) => {
                        if !delivery.case_is_current(&replay) {
                            replay.redis.fail_pubsub_input(delivery.push,delivery.case_id.as_deref(),"Pub/Sub input Case changed during delivery");
                            if let Some(m) = &delivery.matched { replay.redis.fail_exchange(m, "callback case changed during delivery".into()); }
                            continue;
                        }
                        replay.redis.pubsub.complete(delivery.push);
                        input_timing::delivered(&mut replay, timing_scope.as_ref(),
                            crate::replay::control::input_timing::DeliveryReference::NativePush(delivery.push));
                        replay.redis.lifecycle.notify_waiters();
                        if let Some(m) = &delivery.matched { replay.redis.complete_exchange(m); }
                    }
                    Err(error) => {
                        replay.redis.fail_pubsub_input(delivery.push,delivery.case_id.as_deref(),"Pub/Sub input TCP delivery failed");
                        if let Some(m) = &delivery.matched { replay.redis.fail_exchange(m, error.to_string()); }
                        return Err(error.into());
                    }
                }
                continue;
            }
        };
        let frame = match read {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                record_runtime_unsafe(
                    &state,
                    &target_key,
                    "redis",
                    "parse_error",
                    error.to_string(),
                )
                .await;
                return Err(error);
            }
        };
        let request_started = tokio::time::Instant::now();
        let command = match redis_command(&frame.raw) {
            Ok(command) => command,
            Err(error) => {
                record_runtime_unsafe(
                    &state,
                    &target_key,
                    "redis",
                    "parse_error",
                    error.to_string(),
                )
                .await;
                return Err(error);
            }
        };
        let stopping = {
            let state = state.lock().await;
            state.target_session_stopped
                || state.async_case_quiescing()
                || state
                    .active_case_id
                    .as_ref()
                    .is_some_and(|case| state.target_stop_prepared.contains(case))
        };
        if stopping {
            control.reset()?;
            return Ok(());
        }
        if redis_is_unsupported(&command) {
            let mut replay_state = state.lock().await;
            let case_id = replay_state.active_case_id.clone();
            let target_event_index = replay_state
                .redis
                .events
                .request_order
                .reserve(case_id.as_deref());
            replay_state
                .redis
                .events
                .unsupported
                .push(CommandRequestReport {
                    target_observation_id: None,
                    case_id,
                    target: target_key.clone(),
                    command: command.name.clone(),
                    target_event_index: Some(target_event_index),
                    request_fingerprint: None,
                    reason: "Redis command mode is unsupported for replay".to_string(),
                    diagnostic: None,
                });
            drop(replay_state);
            reader
                .inner
                .write_all(b"-ERR Redis command mode is unsupported for replay\r\n")
                .await?;
            continue;
        }
        let (recorded_failure_case_id, recorded_failure) = if redis_is_builtin(&command.name) {
            let mut state = state.lock().await;
            let active_case_id = state.active_case_id.clone();
            let bound_connection = connection_binding.connection(active_case_id.as_deref());
            let matched = state.redis.match_redis_builtin_failure(
                active_case_id.as_deref(),
                &target_key,
                TargetConnection {
                    id: client_id,
                    bound: bound_connection,
                },
                resp_version,
                database,
                username.as_deref(),
                &command,
            );
            (active_case_id, matched)
        } else {
            (None, None)
        };
        if let Some(matched) = recorded_failure {
            if matched.requires_binding {
                connection_binding.bind(recorded_failure_case_id.as_deref(), matched.connection_id);
            }
            if deliver_redis_exchange(
                &mut reader,
                &state,
                &matched,
                &control,
                request_started,
                client_id,
            )
            .await?
            {
                break;
            }
            continue;
        }
        if let Some(response) =
            redis_builtin(&command, &mut resp_version, &mut database, &mut username)
        {
            reader.inner.write_all(&response).await?;
            if command.name == "QUIT" {
                break;
            }
            continue;
        }
        let response = admission::match_command(
            &state,
            &target_key,
            client_id,
            &mut connection_binding,
            resp_version,
            database,
            username.as_deref(),
            &command,
        )
        .await;
        match response {
            Ok(matched) => {
                if let Err(error) =
                    crate::replay::policy::request_contract::hypotheses::await_durable(&state).await
                {
                    state
                        .lock()
                        .await
                        .redis
                        .fail_exchange(&matched, "hypothesis evidence persistence failed".into());
                    return Err(error);
                }
                let deliveries = state.lock().await.redis.pubsub.subscription(
                    client_id,
                    &target_key,
                    database,
                    username.as_deref(),
                    &command,
                    &matched,
                    push_tx.clone(),
                )?;
                if deliver_redis_exchange(
                    &mut reader,
                    &state,
                    &matched,
                    &control,
                    request_started,
                    client_id,
                )
                .await?
                {
                    break;
                }
                if let Some(deliveries) = deliveries {
                    pubsub::schedule_notifications(state.clone(), deliveries);
                }
            }
            Err(_) => break,
        }
    }
    Ok(())
}

async fn record_runtime_unsafe(
    state: &Arc<Mutex<ReplayState>>,
    target: &TargetKey,
    _protocol: &str,
    command: &str,
    reason: String,
) {
    let mut state = state.lock().await;
    let request = CommandRequestReport {
        target_observation_id: None,
        case_id: state.active_case_id.clone(),
        target: target.clone(),
        command: command.to_string(),
        target_event_index: None,
        request_fingerprint: None,
        reason,
        diagnostic: None,
    };
    if let Some(case_id) = &request.case_id {
        state.redis.events.dirty_case_ids.insert(case_id.clone());
    }
    state.redis.events.unsafe_events.push(request);
}

impl RecordedCapture {
    fn decode(&self) -> Result<Vec<u8>> {
        if self.truncated {
            return Err(anyhow!("recorded Redis capture is truncated"));
        }
        match self.encoding.as_str() {
            "base64" => STANDARD
                .decode(&self.data)
                .context("invalid Redis capture base64"),
            "utf8" => Ok(self.data.as_bytes().to_vec()),
            other => Err(anyhow!("unsupported Redis capture encoding {other}")),
        }
    }
}

fn register_target(
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    host: &str,
    port: u16,
    protocol: ReplayProtocol,
) -> Result<()> {
    register_replay_target(
        targets,
        &TargetKey {
            host: normalize_host(host),
            port,
        },
        protocol,
    )
}

fn validate_recorded_exchange(
    event_type: &str,
    command: &str,
    replay_safe: bool,
    truncated: bool,
) -> Result<()> {
    if !replay_safe || truncated {
        return Err(anyhow!(
            "{event_type} command {command} contains unsafe or truncated replay evidence"
        ));
    }
    Ok(())
}

fn validate_subscription_exchange(
    record: &RecordedExchange,
    args: &[Vec<u8>],
    response: &[u8],
) -> Result<()> {
    if record.lifecycle_cleanup {
        return Ok(());
    }
    if !is_pubsub_command(&record.command) || record.outcome.termination().is_some() {
        return Ok(());
    }

    ensure!(
        record.resp_version == 2,
        "Redis Pub/Sub replay requires RESP2"
    );
    ensure!(
        args.len() == 1,
        "Redis {} confirmation replay requires exactly one subscription argument",
        record.command
    );

    let command = RedisCommand {
        name: record.command.clone(),
        args: args.to_vec(),
    };
    match record.response_kind.as_str() {
        "array" => validate_subscription_confirmation(&command, response),
        "error" => {
            let raw = bytes::Bytes::copy_from_slice(response);
            ensure!(
                redis_frame_kind(&raw)? == RedisFrameKind::Error,
                "Redis {} recorded error response is not a RESP2 error frame",
                record.command
            );
            Ok(())
        }
        other => Err(anyhow!(
            "Redis {} replay requires an exact subscription confirmation or error, got {other}",
            record.command
        )),
    }
}

fn target_matches(target: &TargetKey, host: &str, port: u16) -> bool {
    target.host == normalize_host(host) && target.port == port
}

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn unused_iter(
    exchanges: &[ReplayExchange],
    source: ReplaySource,
) -> impl Iterator<Item = CommandUnusedReport> + '_ {
    exchanges
        .iter()
        .enumerate()
        .filter(move |(_, exchange)| {
            exchange.source.matches_scope(source)
                && if exchange.reusable_snapshot {
                    !exchange.matched_once
                } else {
                    !exchange.status.is_consumed()
                }
        })
        .map(move |(index, exchange)| CommandUnusedReport {
            index,
            case_id: exchange.case_id.clone(),
            source: exchange.source,
            target: TargetKey {
                host: normalize_host(&exchange.record.target_host),
                port: exchange.record.target_port,
            },
            connection_id: exchange.record.connection_id,
            sequence: exchange.record.sequence,
            command: exchange.record.command.clone(),
        })
}

fn unused(exchanges: &[ReplayExchange], source: ReplaySource) -> Vec<CommandUnusedReport> {
    unused_iter(exchanges, source)
        .take(if source.is_run_owned() {
            100
        } else {
            usize::MAX
        })
        .collect()
}

#[cfg(test)]
mod tests;

impl RecordedExchange {
    fn run_owner_kind(&self) -> Option<&'static str> {
        self.capture
            .as_ref()
            .and_then(|capture| match capture.owner_kind() {
                "case" => None,
                kind => Some(kind),
            })
    }
}
