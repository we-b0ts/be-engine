//! Read-only notification identity and sparse session state, separate from delivery.
use super::*;
use serde_json::json;

pub(crate) use traffic_protocol_redis::report::NotificationIdentity;
pub(crate) use traffic_replay::report::DeliveryDelta as NotificationDelta;

pub(crate) struct NotificationLaneEvidence {
    pub source: Arc<RecordSource>,
    pub pages: Paged<NotificationEntry>,
    pub identity: NotificationIdentity,
}

pub(crate) type NotificationSessionEvidence =
    traffic_replay::report::DeliverySession<NotificationLaneEvidence>;

impl IndexedNotifications {
    pub(in crate::replay::redis::pubsub) fn evidence(
        &self,
        subscriptions: &BTreeMap<(Uuid, u64), (usize, RecordedExchange)>,
    ) -> Result<NotificationSessionEvidence> {
        let mut lanes = Vec::new();
        let mut deltas = Vec::new();
        for (index, lane) in self.lanes.iter().enumerate() {
            lane.source.validate()?;
            let anchor = (lane.record.connection_id, lane.record.subscription_sequence);
            let (_, subscription) = subscriptions
                .get(&anchor)
                .context("notification subscription proof missing at finalization")?;
            lanes.push(NotificationLaneEvidence {
                source: lane.source.clone(),
                pages: lane
                    .pages
                    .clone()
                    .context("notification index is not sealed")?,
                identity: NotificationIdentity {
                    target: TargetKey {
                        host: normalize_host(&lane.record.target_host),
                        port: lane.record.target_port,
                    },
                    database: lane.record.database,
                    username: lane.record.username.clone(),
                    connection_id: anchor.0,
                    subscription_sequence: anchor.1,
                    kind: match lane.kind {
                        RedisSubscriptionKind::Channel => "channel",
                        RedisSubscriptionKind::Pattern => "pattern",
                        RedisSubscriptionKind::ShardChannel => "shard_channel",
                    }
                    .into(),
                    subject: lane.subject.clone(),
                    // Keep the confirmed native command, without its Case/Global
                    // alias classification, which differs by selected API.
                    subscription_proof: json!({
                        "command": subscription.command,
                        "args": subscription.args,
                        "response_kind": subscription.response_kind,
                        "response": subscription.response,
                    }),
                },
            });
            let mut delta = NotificationDelta {
                lane: index,
                ..Default::default()
            };
            for (&position, status) in &lane.statuses {
                match status {
                    ReplayExchangeStatus::Consumed => delta.consumed.push(position),
                    ReplayExchangeStatus::Failed => delta.failed.push(position),
                    ReplayExchangeStatus::Responding => delta.responding.push(position),
                    ReplayExchangeStatus::Available | ReplayExchangeStatus::StartupBlocked => {}
                    ReplayExchangeStatus::AwaitingClientTermination
                    | ReplayExchangeStatus::Cancelled => {
                        anyhow::bail!("invalid notification delivery status")
                    }
                }
            }
            if !lane.statuses.is_empty() {
                deltas.push(delta);
            }
        }
        Ok(NotificationSessionEvidence {
            lanes,
            deltas,
            recorded: self.total,
            delivered: self.delivered,
            failed: self.failed,
        })
    }
}
