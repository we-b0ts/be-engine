//! Finite RESP2 notifications and subscription delivery; RPC codecs are adapters.
use super::*;
use crate::redis::{RedisSubscriptionKind, parse_pubsub_push, socketio_rpc as rpc};
use std::path::Path;
use tokio::sync::mpsc;
mod adapter;
pub(super) struct RpcComparison {
    pub source: Vec<Vec<u8>>,
    pub actual: Vec<Vec<u8>>,
}
mod inventory;
pub(in crate::replay) use inventory::{
    NotificationDelta, NotificationIdentity, NotificationLaneEvidence, NotificationSessionEvidence,
};
mod notifications;
mod report_inventory;
pub(in crate::replay) mod subscription_evidence;
pub(super) use notifications::{NotificationJob, schedule_notifications};
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Deserialize)]
pub(in crate::replay) struct RecordedPush {
    pub(super) target_host: String,
    pub(super) target_port: u16,
    pub(super) database: i64,
    pub(super) username: Option<String>,
    pub(super) connection_id: Uuid,
    pub(super) subscription_sequence: u64,
    pub(super) rpc_request: Option<RequestRef>,
    pub(super) response: RecordedCapture,
    pub(super) duration_ms: u64,
    pub(super) replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(in crate::replay) struct RequestRef {
    pub(super) connection_id: Uuid,
    pub(super) sequence: u64,
}

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
}

#[derive(Debug, Clone, Copy)]
pub(super) enum PushId {
    Inline(usize),
    Indexed { lane: usize, index: usize },
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
pub(in crate::replay) struct PubSubState {
    global_report: crate::replay::report::global_evidence::regular_usage::Usage,
    subscription_mirrors: BTreeMap<(Uuid, u64), RecordedExchange>,
    indexed: inventory::IndexedNotifications,
    pushes: Vec<Push>,
    subscriptions: Vec<Subscription>,
    bindings: adapter::Bindings,
    notifications: std::collections::HashMap<(Uuid, u64), Arc<Vec<usize>>>,
    delivered: usize,
    failed: usize,
    callbacks: usize,
    delivered_callbacks: usize,
    cases: std::collections::HashMap<String, Vec<usize>>,
}

impl PubSubState {
    pub(in crate::replay) fn register_indexed(
        &mut self,
        record: RecordedPush,
        reference: crate::dependency_index::RecordRef,
    ) -> Result<()> {
        if record.rpc_request.is_none() {
            return self.indexed.register(record, reference);
        }
        self.register(record, ReplaySource::Global, None)?;
        let push = self.pushes.last_mut().expect("registered push");
        push.report_index = Some(reference.location.line - 1);
        push.evidence = Some(reference);
        push.raw = Vec::new();
        push.record.response.data = String::new();
        Ok(())
    }

    pub(in crate::replay) fn finish_indexed(&mut self) -> Result<()> {
        self.indexed.seal()
    }
    pub(in crate::replay) fn restore_indexed(
        &mut self,
        lanes: Vec<crate::dependency_index::global::NotificationLane>,
        root: &Path,
        source: Arc<crate::dependency_index::RecordSource>,
    ) -> Result<()> {
        self.indexed.restore(lanes, root, source)
    }

    pub(super) fn case_is_dirty(&self, case: &str) -> bool {
        self.cases.get(case).is_some_and(|indices| {
            indices
                .iter()
                .any(|index| self.pushes[*index].status != ReplayExchangeStatus::Consumed)
        })
    }
    pub(super) fn report(&self) -> Option<crate::replay::report::command::PubSubReport> {
        (!self.pushes.is_empty() || self.indexed.total > 0).then(|| {
            crate::replay::report::command::PubSubReport {
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

    pub(in crate::replay) fn register(
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
                source == ReplaySource::Global,
                "uncorrelated Redis Pub/Sub notifications require Global process ownership"
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
            .take(if source == ReplaySource::Global {
                100
            } else {
                usize::MAX
            })
            .map(|(index, p)| CommandUnusedReport {
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
        if source == ReplaySource::Global {
            result.extend(self.indexed.unused(100usize.saturating_sub(result.len())));
        }
        result
    }

    pub(super) fn global_unused_count(&self) -> usize {
        self.pushes
            .iter()
            .filter(|p| {
                p.source == ReplaySource::Global && p.status != ReplayExchangeStatus::Consumed
            })
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
            .filter(|(_, p)| p.source == ReplaySource::Global && !p.status.is_consumed())
        {
            visitor(serde_json::to_value(CommandUnusedReport {
                index: push.report_index.unwrap_or(index),
                case_id: None,
                source: ReplaySource::Global,
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

    pub(in crate::replay::redis) fn notification_evidence(
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
    delivery: Delivery,
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
        if closed
            || replay.finalized_at.is_some()
            || delivery
                .matched
                .as_ref()
                .is_some_and(|m| m.report.case_id != replay.active_case_id)
        {
            replay.redis.pubsub.fail(delivery.push);
            if let Some(matched) = &delivery.matched {
                replay.redis.fail_exchange(
                    matched,
                    "RPC callback subscriber closed or case ended".into(),
                );
            }
            return;
        }
        let sender = match sender {
            Some(sender) => sender,
            None => match replay
                .redis
                .pubsub
                .rpc_sender(delivery.matched.as_ref().expect("RPC delivery"))
            {
                Ok(sender) => sender,
                Err(error) => {
                    replay.redis.pubsub.fail(delivery.push);
                    replay.redis.fail_exchange(
                        delivery.matched.as_ref().expect("RPC delivery"),
                        error.to_string(),
                    );
                    return;
                }
            },
        };
        if sender.try_send(delivery.clone()).is_err() {
            replay.redis.pubsub.fail(delivery.push);
            if let Some(matched) = &delivery.matched {
                replay.redis.fail_exchange(
                    matched,
                    "Redis Pub/Sub subscriber unavailable or queue full".into(),
                );
            }
        }
    });
}
