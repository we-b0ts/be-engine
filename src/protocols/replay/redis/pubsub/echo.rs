//! Finite Socket.IO adapter self-echoes follow admitted PUBLISH calls, not subscription age.
use super::*;
use crate::dependency_index::RecordRef;
use inventory::NotificationEntry;
use std::collections::BTreeMap;
use std::sync::OnceLock;
mod preparation;

pub(in crate::protocols::replay::redis) use traffic_protocol_redis::pubsub::echo::Prepared;
pub(super) use traffic_protocol_redis::pubsub::echo::{Digest, Echoes};

pub(super) type EchoIndex =
    std::result::Result<BTreeMap<Digest, Vec<(usize, NotificationEntry)>>, String>;

type InlineEcho = (usize, Option<chrono::DateTime<chrono::Utc>>, Vec<u8>);

struct Job {
    client: Uuid,
    sender: mpsc::Sender<Delivery>,
    inventory: JobInventory,
}
enum JobInventory {
    Indexed {
        lane: usize,
        source: Arc<crate::dependency_index::RecordSource>,
        index: Arc<OnceLock<EchoIndex>>,
    },
    Inline(Vec<InlineEcho>),
}

impl PubSubState {
    pub(in crate::protocols::replay::redis) fn prepare_echo(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<Prepared> {
        self.is_adapter_source(exchange).then_some(())?;
        self.echoes
            .prepare(&exchange.record.native, &exchange.args, args)
    }

    pub(super) fn timer_controls_echo(&self, id: PushId, digest: Option<Digest>) -> bool {
        let (record, kind) = match id {
            PushId::Inline(index) => (&self.pushes[index].record, self.pushes[index].kind),
            PushId::Indexed { lane, .. } => (
                &self.indexed.lanes[lane].record,
                self.indexed.lanes[lane].kind,
            ),
        };
        if kind == RedisSubscriptionKind::ShardChannel {
            return false;
        }
        self.echoes.controls(record, digest)
    }

    fn echo_jobs(&self, matched: &MatchedRedisExchange, prepared: &Prepared) -> Vec<Job> {
        self.subscriptions
            .iter()
            .filter_map(|sub| {
                if sub.sender.is_closed()
                    || sub.target != matched.report.target
                    || (sub.kind == RedisSubscriptionKind::Channel
                        && sub.subject != prepared.source[0])
                    || sub.kind == RedisSubscriptionKind::ShardChannel
                {
                    return None;
                }
                let inventory = if let Some((lane, _, source)) =
                    self.indexed.job(sub.source_connection, sub.sequence)
                {
                    let indexed = &self.indexed.lanes[lane];
                    if indexed.record.database != sub.database
                        || indexed.record.username != sub.username
                    {
                        return None;
                    }
                    JobInventory::Indexed {
                        lane,
                        source,
                        index: indexed.echoes.clone(),
                    }
                } else {
                    let pushes = self
                        .notifications
                        .get(&(sub.source_connection, sub.sequence))?;
                    JobInventory::Inline(
                        pushes
                            .iter()
                            .filter_map(|&index| {
                                let push = &self.pushes[index];
                                (push.record.database == sub.database
                                    && push.record.username == sub.username)
                                    .then(|| {
                                        push.bytes()
                                            .ok()
                                            .map(|bytes| (index, push.record.timestamp, bytes))
                                    })
                                    .flatten()
                            })
                            .collect(),
                    )
                };
                Some(Job {
                    client: sub.client,
                    sender: sub.sender.clone(),
                    inventory,
                })
            })
            .collect()
    }
}

fn candidates(job: &JobInventory, prepared: &Prepared) -> Result<Vec<(PushId, Vec<u8>)>> {
    let mut candidates = Vec::new();
    match job {
        JobInventory::Indexed {
            lane,
            source,
            index,
        } => {
            let lookup = index
                .get()
                .context("adapter echo index was not prepared before Replay readiness")?
                .as_ref()
                .map_err(|error| anyhow!("adapter echo index unavailable: {error}"))?;
            if let Some(entries) = lookup.get(&prepared.digest) {
                let selected = prepared.select(
                    entries
                        .iter()
                        .map(|(index, entry)| (*index, entry.timestamp)),
                )?;
                for (index, entry) in entries.iter().filter(|(index, _)| selected.contains(index)) {
                    let reference: RecordRef = source.reference(entry.location.clone());
                    let raw = reference.load::<RecordedPush>()?.response.decode()?;
                    candidates.push((
                        PushId::Indexed {
                            lane: *lane,
                            index: *index,
                        },
                        prepared.render(&raw)?,
                    ));
                }
            }
        }
        JobInventory::Inline(pushes) => {
            let mut echoes = Vec::new();
            for (index, timestamp, raw) in pushes {
                let frame = parse_pubsub_push(raw)?.context("invalid adapter notification")?;
                if frame.channel == prepared.source[0] && frame.payload == prepared.source[1] {
                    echoes.push((*index, *timestamp, raw));
                }
            }
            let selected = prepared.select(
                echoes
                    .iter()
                    .map(|(index, timestamp, _)| (*index, *timestamp)),
            )?;
            for (index, _, raw) in echoes
                .into_iter()
                .filter(|(index, _, _)| selected.contains(index))
            {
                candidates.push((PushId::Inline(index), prepared.render(raw)?));
            }
        }
    }
    Ok(candidates)
}

pub(in crate::protocols::replay::redis) async fn deliver(
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedRedisExchange,
    serial_scope: Option<&super::super::input_timing::DeliveryScope>,
) -> Result<()> {
    let Some(prepared) = &matched.adapter_echo else {
        return Ok(());
    };
    let jobs = {
        let replay = state.lock().await;
        replay.protocols.redis.pubsub.echo_jobs(matched, prepared)
    };
    for job in jobs {
        let prepared = prepared.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            candidates(&job.inventory, &prepared)
                .map(|candidates| (job.client, job.sender, candidates))
        })
        .await??;
        let (client, sender, candidates) = loaded;
        let mut replay = state.lock().await;
        ensure!(
            replay.finalized_at.is_none(),
            "Replay finalized during adapter self-echo delivery"
        );
        ensure!(
            serial_scope.is_none()
                || super::super::delivery::serial_scope_current(&replay, serial_scope),
            "deferred adapter self-echo lost its Case"
        );
        let case_id = serial_scope.and(matched.report.case_id.as_deref());
        let request_epoch =
            case_id.and_then(|case| replay.protocols.redis.native_request_epoch(case));
        for (id, bytes) in candidates {
            ensure!(
                replay.protocols.redis.pubsub.is_subscribed(client, id),
                "adapter echo subscriber closed"
            );
            let available = match id {
                PushId::Inline(index) => replay.protocols.redis.pubsub.pushes[index]
                    .status
                    .is_available(),
                PushId::Indexed { lane, index } => {
                    replay.protocols.redis.pubsub.indexed.available(lane, index)
                }
            };
            ensure!(available, "recorded adapter self-echo already claimed");
            match id {
                PushId::Inline(index) => {
                    replay.protocols.redis.pubsub.pushes[index].status =
                        ReplayExchangeStatus::Responding
                }
                PushId::Indexed { lane, index } => replay
                    .protocols
                    .redis
                    .pubsub
                    .indexed
                    .responding(lane, index),
            }
            if sender
                .try_send(Delivery {
                    case_id: case_id.map(str::to_owned),
                    push: id,
                    bytes,
                    matched: None,
                    request_epoch,
                    value: None,
                })
                .is_err()
            {
                replay.protocols.redis.pubsub.fail(id);
                anyhow::bail!("adapter echo delivery queue unavailable");
            }
        }
    }
    Ok(())
}
