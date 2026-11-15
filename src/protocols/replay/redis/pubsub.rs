//! Finite RESP2 notifications and subscription delivery; RPC codecs are adapters.
use super::*;
use crate::redis::{RedisSubscriptionKind, parse_pubsub_push, socketio_rpc as rpc};
use std::path::Path;
use tokio::sync::mpsc;
mod adapter;
mod delivery;
mod subject_delivery;
mod value_delivery;
pub(super) use delivery::deliver_input;
pub(super) mod echo;
pub(super) struct RpcComparison {
    pub source: Vec<Vec<u8>>,
    pub actual: Vec<Vec<u8>>,
}
pub(crate) mod ingress;
mod inventory;
pub(crate) mod native_clock;
pub(crate) use inventory::{
    NotificationDelta, NotificationIdentity, NotificationLaneEvidence, NotificationSessionEvidence,
};
mod finite_inventory;
mod input_timing;
pub(crate) mod namespace_sessions;
mod notifications;
mod report_inventory;
pub(crate) mod subscription_evidence;
pub(super) use notifications::{NotificationJob, schedule_notifications};
#[cfg(test)]
mod tests;

pub(crate) use traffic_protocol_redis::recorded::RecordedPush;

#[derive(Debug)]
struct Push {
    evidence: Option<crate::dependency_index::RecordRef>,
    report_index: Option<usize>,
    kind: RedisSubscriptionKind,
    subject: Vec<u8>,
    record: RecordedPush,
    raw: Vec<u8>,
    source: ReplaySource,
    case_id: Option<String>,
    status: ReplayExchangeStatus,
    linked: bool,
}

#[derive(Debug, Clone)]
pub(super) struct Delivery {
    pub(super) push: PushId,
    pub(super) bytes: Vec<u8>,
    pub(super) matched: Option<MatchedRedisExchange>,
    pub(super) case_id: Option<String>,
    pub(super) request_epoch: Option<chrono::DateTime<chrono::Utc>>,
    pub(super) value: Option<value_delivery::Prepared>,
}

impl Delivery {
    pub(super) fn case_is_current(&self, replay: &ReplayState) -> bool {
        let active = replay.active_case_id.as_deref();
        let stopped = replay.target_session_stopped;
        self.matched
            .as_ref()
            .is_none_or(|matched| matched.report.case_id.as_deref() == active)
            && self
                .case_id
                .as_deref()
                .is_none_or(|case| !stopped && Some(case) == active)
            && self.request_epoch.is_none_or(|epoch| {
                self.case_id.as_deref().is_some_and(|case| {
                    replay.protocols.redis.native_request_epoch(case) == Some(epoch)
                })
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum PushId {
    Inline(usize),
    Indexed { lane: usize, index: usize },
}

impl PushId {
    fn timing_reference(self) -> crate::replay::control::input_timing::DeliveryReference {
        let identity = match self {
            Self::Inline(index) => serde_json::json!({"kind":"inline", "index":index}),
            Self::Indexed { lane, index } => {
                serde_json::json!({"kind":"indexed", "lane":lane, "index":index})
            }
        };
        let reference = traffic_model::recording::ProtocolRef::new("redis_notification", identity)
            .expect("notification position is an object");
        crate::replay::control::input_timing::DeliveryReference::Native(Arc::new(reference))
    }
}

#[derive(Debug)]
struct Subscription {
    _cancel: tokio::sync::watch::Sender<()>,
    client: Uuid,
    target: TargetKey,
    database: i64,
    username: Option<String>,
    source_connection: Uuid,
    sequence: u64,
    kind: RedisSubscriptionKind,
    subject: Vec<u8>,
    sender: mpsc::Sender<Delivery>,
}

#[derive(Debug, Default)]
pub(crate) struct PubSubState {
    global_report: crate::replay::report::global_evidence::regular_usage::Usage,
    subscription_mirrors: BTreeMap<(Uuid, u64), RecordedExchange>,
    indexed: inventory::IndexedNotifications,
    pushes: Vec<Push>,
    subscriptions: Vec<Subscription>,
    bindings: adapter::Bindings,
    echoes: echo::Echoes,
    ingress: ingress::Ingress,
    pub(crate) native_clock: native_clock::NativeClock,
    pub(crate) namespace_sessions: namespace_sessions::NamespaceSessions,
    case_deliveries: BTreeMap<PushId, (String, Uuid)>,
    notifications: std::collections::HashMap<(Uuid, u64), Arc<Vec<usize>>>,
    delivered: usize,
    failed: usize,
    callbacks: usize,
    delivered_callbacks: usize,
    cases: std::collections::HashMap<String, Vec<usize>>,
    value_producers: Option<value_delivery::causality::Producers>,
}

impl PubSubState {
    pub(crate) fn register_indexed(
        &mut self,
        record: RecordedPush,
        reference: crate::dependency_index::RecordRef,
        source_kind: ReplaySource,
    ) -> Result<()> {
        if record.rpc_request.is_none() {
            let before = self.indexed.lanes.len();
            self.indexed.register(record, reference)?;
            for lane in &mut self.indexed.lanes[before..] {
                lane.source_kind = source_kind;
            }
            return Ok(());
        }
        self.register(record, source_kind, None)?;
        let push = self.pushes.last_mut().expect("registered push");
        push.report_index = Some(reference.location.line - 1);
        push.evidence = Some(reference);
        push.raw = Vec::new();
        push.record.response.data = String::new();
        Ok(())
    }

    pub(crate) fn finish_indexed(&mut self) -> Result<()> {
        self.indexed.seal()
    }
    pub(crate) fn restore_indexed(
        &mut self,
        lanes: Vec<crate::dependency_index::global::NotificationLane>,
        root: &Path,
        source: Arc<crate::dependency_index::RecordSource>,
        source_kind: ReplaySource,
    ) -> Result<()> {
        self.indexed.restore(lanes, root, source, source_kind)
    }

    pub(super) fn case_is_dirty(&self, case: &str) -> bool {
        self.cases.get(case).is_some_and(|indices| {
            indices
                .iter()
                .any(|index| self.pushes[*index].status != ReplayExchangeStatus::Consumed)
        })
    }
    pub(super) fn report(&self) -> Option<crate::protocols::replay::redis::report::PubSubReport> {
        (!self.pushes.is_empty() || self.indexed.total > 0).then(|| {
            crate::protocols::replay::redis::report::PubSubReport {
                recorded_pushes: self.pushes.len() + self.indexed.total,
                delivered_pushes: self.delivered + self.indexed.delivered,
                recorded_rpc_callbacks: self.callbacks,
                delivered_rpc_callbacks: self.delivered_callbacks,
                failed_pushes: self.failed + self.indexed.failed,
            }
        })
    }
    pub(super) fn is_subscribed(&self, client: Uuid, index: PushId) -> bool {
        let record = match index {
            PushId::Inline(index) => &self.pushes[index].record,
            PushId::Indexed { lane, .. } => &self.indexed.lanes[lane].record,
        };
        self.subscriptions.iter().any(|s| {
            s.client == client
                && s.source_connection == record.connection_id
                && s.sequence == record.subscription_sequence
                && !s.sender.is_closed()
        })
    }

    pub(crate) fn register(
        &mut self,
        record: RecordedPush,
        source: ReplaySource,
        case_id: Option<&str>,
    ) -> Result<()> {
        ensure!(
            record.replay_safe && !record.response.truncated,
            "unsafe/truncated Redis Pub/Sub evidence"
        );
        let raw = record.response.decode()?;
        ensure!(
            raw.len() <= 64 * 1024 * 1024,
            "Redis Pub/Sub frame exceeds 64 MiB"
        );
        let push = parse_pubsub_push(&raw)?.context("Redis Pub/Sub evidence is not a push")?;
        ensure!(
            record.subscription_sequence > 0,
            "Pub/Sub subscription anchor missing"
        );
        if record.rpc_request.is_some() {
            ensure!(
                rpc::callback(&push.payload)?.is_some(),
                "RPC evidence lacks a valid callback"
            );
        }
        let index = self.pushes.len();
        self.bindings.index(&record, source, case_id, index)?;
        if record.rpc_request.is_none() {
            ensure!(
                source.is_run_level() || source == ReplaySource::Case && case_id.is_some(),
                "Redis Pub/Sub notifications require their original Case or run owner"
            );
            Arc::make_mut(
                self.notifications
                    .entry((record.connection_id, record.subscription_sequence))
                    .or_default(),
            )
            .push(index);
        }
        if let Some(case) = case_id {
            self.cases.entry(case.to_owned()).or_default().push(index);
        }
        self.callbacks += usize::from(record.rpc_request.is_some());
        let kind = push.subscription_kind;
        let subject = push.subject.clone();
        self.pushes.push(Push {
            evidence: None,
            report_index: None,
            kind,
            subject,
            record,
            raw,
            source,
            case_id: case_id.map(str::to_owned),
            status: ReplayExchangeStatus::Available,
            linked: false,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn subscription(
        &mut self,
        client: Uuid,
        target: &TargetKey,
        database: i64,
        username: Option<&str>,
        command: &RedisCommand,
        matched: &MatchedRedisExchange,
        sender: mpsc::Sender<Delivery>,
    ) -> Result<Option<NotificationJob>> {
        if matched.response.starts_with(b"-")
            || !is_pubsub_command(&command.name)
            || matched.timing.outcome().termination().is_some()
            || matched.timing.outcome().is_client_terminated()
        {
            return Ok(None);
        }
        let kind = match command.name.as_str() {
            "SUBSCRIBE" | "UNSUBSCRIBE" => RedisSubscriptionKind::Channel,
            "PSUBSCRIBE" | "PUNSUBSCRIBE" => RedisSubscriptionKind::Pattern,
            _ => RedisSubscriptionKind::ShardChannel,
        };
        let subject = command.args[0].clone();
        self.subscriptions.retain(|s| {
            !s.sender.is_closed() && !(s.client == client && s.kind == kind && s.subject == subject)
        });
        if command.name.contains("UNSUBSCRIBE") {
            return Ok(None);
        }
        ensure!(
            self.subscriptions.len() < 4096,
            "Redis Pub/Sub subscription limit exceeded"
        );
        let (cancel, cancelled) = tokio::sync::watch::channel(());
        self.subscriptions.push(Subscription {
            _cancel: cancel,
            client,
            target: target.clone(),
            database,
            username: username.map(str::to_owned),
            source_connection: matched.connection_id,
            sequence: matched.report.sequence,
            kind,
            subject,
            sender: sender.clone(),
        });
        let indexed = self
            .indexed
            .job(matched.connection_id, matched.report.sequence);
        let indices = self
            .notifications
            .get(&(matched.connection_id, matched.report.sequence))
            .cloned()
            .unwrap_or_default();
        Ok(
            (indexed.is_some() || !indices.is_empty()).then_some(NotificationJob {
                indices,
                indexed,
                sender,
                cancelled,
                client,
            }),
        )
    }

    pub(super) fn complete(&mut self, id: PushId) {
        self.case_deliveries.remove(&id);
        self.complete_ingress(id);
        let index = match id {
            PushId::Inline(index) => index,
            PushId::Indexed { lane, index } => {
                self.indexed.complete(lane, index);
                return;
            }
        };
        if self.pushes[index].status == ReplayExchangeStatus::Consumed {
            return;
        }
        if self.pushes[index].status == ReplayExchangeStatus::Failed {
            self.failed -= 1;
        }
        self.delivered += 1;
        self.delivered_callbacks += usize::from(self.pushes[index].record.rpc_request.is_some());
        self.pushes[index].status = ReplayExchangeStatus::Consumed;
        self.refresh_global_report(index);
    }
    pub(super) fn fail(&mut self, id: PushId) {
        self.case_deliveries.remove(&id);
        self.fail_ingress(id);
        let index = match id {
            PushId::Inline(index) => index,
            PushId::Indexed { lane, index } => {
                self.indexed.fail(lane, index);
                return;
            }
        };
        if matches!(
            self.pushes[index].status,
            ReplayExchangeStatus::Failed | ReplayExchangeStatus::Consumed
        ) {
            return;
        }
        self.failed += 1;
        self.pushes[index].status = ReplayExchangeStatus::Failed;
        self.refresh_global_report(index);
    }

    pub(super) fn unused(&self, source: ReplaySource) -> Vec<CommandUnusedReport> {
        let mut result: Vec<_> = self
            .pushes
            .iter()
            .enumerate()
            .filter(|(_, p)| p.source == source && p.status != ReplayExchangeStatus::Consumed)
            .take(if source.is_run_level() {
                100
            } else {
                usize::MAX
            })
            .map(|(index, p)| CommandUnusedReport {
                source_exchange_id: p.record.source_exchange_id(),
                index: p.report_index.unwrap_or(index),
                case_id: p.case_id.clone(),
                source,
                target: TargetKey {
                    host: normalize_host(&p.record.target_host),
                    port: p.record.target_port,
                },
                connection_id: p.record.connection_id,
                sequence: p.record.subscription_sequence,
                command: "PUBSUB_PUSH".into(),
            })
            .collect();
        if source.is_run_level() {
            result.extend(self.indexed.unused(100usize.saturating_sub(result.len())));
        }
        result
    }

    pub(super) fn global_unused_count(&self) -> usize {
        self.pushes
            .iter()
            .filter(|p| p.source.is_run_level() && p.status != ReplayExchangeStatus::Consumed)
            .count()
            + self.indexed.total
            - self.indexed.delivered
    }

    pub(super) fn visit_global_inline_unused(
        &self,
        visitor: &mut dyn FnMut(serde_json::Value) -> Result<()>,
    ) -> Result<()> {
        for (index, push) in self
            .pushes
            .iter()
            .enumerate()
            .filter(|(_, p)| p.source.is_run_level() && !p.status.is_consumed())
        {
            visitor(serde_json::to_value(CommandUnusedReport {
                source_exchange_id: push.record.source_exchange_id(),
                index: push.report_index.unwrap_or(index),
                case_id: None,
                source: push.source,
                target: TargetKey {
                    host: normalize_host(&push.record.target_host),
                    port: push.record.target_port,
                },
                connection_id: push.record.connection_id,
                sequence: push.record.subscription_sequence,
                command: "PUBSUB_PUSH".into(),
            })?)?;
        }
        Ok(())
    }

    pub(in crate::protocols::replay::redis) fn notification_evidence(
        &self,
        exchanges: &[ReplayExchange],
    ) -> Result<NotificationSessionEvidence> {
        self.indexed
            .evidence(&subscription_evidence::loaded_subscriptions(exchanges)?)
    }
}

pub(super) fn schedule(
    state: Arc<Mutex<ReplayState>>,
    delay: u64,
    mut delivery: Delivery,
    sender: Option<mpsc::Sender<Delivery>>,
) {
    let weak = Arc::downgrade(&state);
    tokio::spawn(async move {
        let closed = match sender.as_ref() {
            Some(sender) => tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(delay)) => false,
                _ = sender.closed() => true,
            },
            None => {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                false
            }
        };
        let Some(state) = weak.upgrade() else {
            return;
        };
        let mut replay = state.lock().await;
        let detached = delivery
            .matched
            .as_ref()
            .is_some_and(|matched| replay.protocols.redis.pubsub.rpc_is_detached(matched));
        if closed
            || replay.finalized_at.is_some()
            || delivery
                .matched
                .as_ref()
                .is_some_and(|m| !detached && m.report.case_id != replay.active_case_id)
        {
            replay.protocols.redis.pubsub.fail(delivery.push);
            if let Some(matched) = &delivery.matched {
                fail_rpc_delivery(
                    &mut replay.protocols.redis,
                    matched,
                    detached,
                    "RPC callback subscriber closed or case ended".into(),
                );
            }
            return;
        }
        let sender = match sender {
            Some(sender) => sender,
            None => match replay
                .protocols
                .redis
                .pubsub
                .rpc_sender(delivery.matched.as_ref().expect("RPC delivery"))
            {
                Ok(sender) => sender,
                Err(error) => {
                    replay.protocols.redis.pubsub.fail(delivery.push);
                    fail_rpc_delivery(
                        &mut replay.protocols.redis,
                        delivery.matched.as_ref().expect("RPC delivery"),
                        detached,
                        error.to_string(),
                    );
                    return;
                }
            },
        };
        let origin = delivery.matched.clone();
        // A late Global callback cannot complete or dirty an already completed
        // publisher Case when the subscriber writer eventually flushes it.
        if detached {
            delivery.matched = None;
        }
        if sender.try_send(delivery.clone()).is_err() {
            replay.protocols.redis.pubsub.fail(delivery.push);
            if let Some(matched) = &origin {
                fail_rpc_delivery(
                    &mut replay.protocols.redis,
                    matched,
                    detached,
                    "Redis Pub/Sub subscriber unavailable or queue full".into(),
                );
            }
        }
    });
}

fn fail_rpc_delivery(
    redis: &mut RedisReplayState,
    matched: &MatchedRedisExchange,
    detached: bool,
    reason: String,
) {
    if detached {
        redis.events.unsafe_events.push(CommandRequestReport {
            target_observation_id: None,
            case_id: None,
            target: matched.report.target.clone(),
            command: "PUBSUB_PUSH".into(),
            target_event_index: None,
            request_fingerprint: None,
            reason,
            diagnostic: None,
        });
    } else {
        redis.fail_exchange(matched, reason);
    }
}
