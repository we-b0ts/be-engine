//! Finite RESP2 notifications and subscription delivery; RPC codecs are adapters.
use super::*;
use crate::redis::{RedisSubscriptionKind, parse_pubsub_push, socketio_rpc as rpc};
use tokio::sync::mpsc;
mod adapter;
pub(super) type ScheduledDelivery = (u64, Delivery, mpsc::Sender<Delivery>);
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
    record: RecordedPush,
    raw: Vec<u8>,
    source: ReplaySource,
    case_id: Option<String>,
    status: ReplayExchangeStatus,
    linked: bool,
}

#[derive(Debug, Clone)]
pub(super) struct Delivery {
    pub(super) push: usize,
    pub(super) bytes: Vec<u8>,
    pub(super) matched: Option<MatchedRedisExchange>,
}

#[derive(Debug)]
struct Subscription {
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
    pushes: Vec<Push>,
    subscriptions: Vec<Subscription>,
    bindings: adapter::Bindings,
    notifications: std::collections::HashMap<(Uuid, u64), Vec<usize>>,
    cases: std::collections::HashMap<String, Vec<usize>>,
}

impl PubSubState {
    pub(super) fn validate_subscriptions(&self, exchanges: &[ReplayExchange]) -> Result<()> {
        let mut subscriptions = std::collections::HashMap::new();
        for exchange in exchanges.iter().filter(|e| {
            matches!(
                e.record.command.as_str(),
                "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE"
            ) && e.record.response_kind != "error"
                && e.record.outcome == DependencyExchangeOutcome::Response
        }) {
            ensure!(
                subscriptions
                    .insert(
                        (exchange.record.connection_id, exchange.record.sequence),
                        exchange
                    )
                    .is_none(),
                "ambiguous recorded Redis subscription identity"
            );
        }
        for push in &self.pushes {
            let subscription = subscriptions.get(&(push.record.connection_id, push.record.subscription_sequence))
                .context("Redis Pub/Sub subscription evidence missing from selection; refresh the recording with its startup subscription")?;
            let frame = parse_pubsub_push(&push.raw)?.expect("validated push");
            let command = match frame.subscription_kind {
                RedisSubscriptionKind::Channel => "SUBSCRIBE",
                RedisSubscriptionKind::Pattern => "PSUBSCRIBE",
                RedisSubscriptionKind::ShardChannel => "SSUBSCRIBE",
            };
            ensure!(
                subscription.record.command == command
                    && subscription.args.first() == Some(&frame.subject)
                    && normalize_host(&subscription.record.target_host)
                        == normalize_host(&push.record.target_host)
                    && subscription.record.target_port == push.record.target_port
                    && subscription.record.database == push.record.database
                    && subscription.record.username == push.record.username,
                "Redis Pub/Sub push does not match its recorded subscription"
            );
        }
        Ok(())
    }

    pub(super) fn case_is_dirty(&self, case: &str) -> bool {
        self.cases.get(case).is_some_and(|indices| {
            indices
                .iter()
                .any(|index| self.pushes[*index].status != ReplayExchangeStatus::Consumed)
        })
    }
    pub(super) fn report(&self) -> Option<crate::replay::report::command::PubSubReport> {
        (!self.pushes.is_empty()).then(|| crate::replay::report::command::PubSubReport {
            recorded_pushes: self.pushes.len(),
            delivered_pushes: self
                .pushes
                .iter()
                .filter(|p| p.status == ReplayExchangeStatus::Consumed)
                .count(),
            recorded_rpc_callbacks: self
                .pushes
                .iter()
                .filter(|p| p.record.rpc_request.is_some())
                .count(),
            delivered_rpc_callbacks: self
                .pushes
                .iter()
                .filter(|p| {
                    p.record.rpc_request.is_some() && p.status == ReplayExchangeStatus::Consumed
                })
                .count(),
            failed_pushes: self
                .pushes
                .iter()
                .filter(|p| p.status == ReplayExchangeStatus::Failed)
                .count(),
        })
    }
    pub(super) fn is_subscribed(&self, client: Uuid, index: usize) -> bool {
        let push = &self.pushes[index];
        self.subscriptions.iter().any(|s| {
            s.client == client
                && s.source_connection == push.record.connection_id
                && s.sequence == push.record.subscription_sequence
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
        ensure!(
            self.pushes.len() < 65536,
            "Redis Pub/Sub inventory exceeds 65536 messages"
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
            self.notifications
                .entry((record.connection_id, record.subscription_sequence))
                .or_default()
                .push(index);
        }
        if let Some(case) = case_id {
            self.cases.entry(case.to_owned()).or_default().push(index);
        }
        self.pushes.push(Push {
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
    ) -> Result<Vec<ScheduledDelivery>> {
        if matched.response.starts_with(b"-") || !is_pubsub_command(&command.name) {
            return Ok(Vec::new());
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
            return Ok(Vec::new());
        }
        ensure!(
            self.subscriptions.len() < 4096,
            "Redis Pub/Sub subscription limit exceeded"
        );
        self.subscriptions.push(Subscription {
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
        let mut deliveries = Vec::new();
        for index in self
            .notifications
            .get(&(matched.connection_id, matched.report.sequence))
            .into_iter()
            .flatten()
        {
            let i = *index;
            let push = &mut self.pushes[i];
            if !push.status.is_available() {
                continue;
            }
            push.status = ReplayExchangeStatus::Responding;
            deliveries.push((
                push.record.duration_ms,
                Delivery {
                    push: i,
                    bytes: push.raw.clone(),
                    matched: None,
                },
                sender.clone(),
            ));
        }
        Ok(deliveries)
    }

    pub(super) fn complete(&mut self, index: usize) {
        self.pushes[index].status = ReplayExchangeStatus::Consumed;
    }
    pub(super) fn fail(&mut self, index: usize) {
        self.pushes[index].status = ReplayExchangeStatus::Failed;
    }

    pub(super) fn unused(&self, source: ReplaySource) -> Vec<CommandUnusedReport> {
        self.pushes
            .iter()
            .enumerate()
            .filter(|(_, p)| p.source == source && p.status != ReplayExchangeStatus::Consumed)
            .map(|(index, p)| CommandUnusedReport {
                index,
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
            .collect()
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
