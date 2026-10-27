//! Finite Socket.IO adapter self-echoes follow admitted PUBLISH calls, not subscription age.
use super::*;
use crate::dependency_index::RecordRef;
use inventory::NotificationEntry;
use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;
mod preparation;

type Digest = [u8; 32];
fn endpoint(record: &RecordedPush) -> TargetKey {
    TargetKey {
        host: normalize_host(&record.target_host),
        port: record.target_port,
    }
}
pub(super) type EchoIndex =
    std::result::Result<BTreeMap<Digest, Vec<(usize, NotificationEntry)>>, String>;

#[derive(Debug, Default)]
pub(super) struct Echoes {
    publishers: HashSet<(TargetKey, Digest)>,
    channels: HashSet<(TargetKey, Vec<u8>)>,
}
impl Echoes {
    pub(super) fn register(&mut self, record: &RecordedExchange, args: &[Vec<u8>]) {
        if let Some(digest) = rpc::echo_digest(&args[0], &args[1]) {
            let target = TargetKey {
                host: normalize_host(&record.target_host),
                port: record.target_port,
            };
            self.publishers.insert((target.clone(), digest));
            self.channels.insert((target, args[0].clone()));
        }
    }
    pub(super) fn controls(&self, record: &RecordedPush, digest: Option<Digest>) -> bool {
        digest.is_some_and(|digest| self.publishers.contains(&(endpoint(record), digest)))
    }
}

#[derive(Debug, Clone)]
pub(in crate::replay::redis) struct Prepared {
    source: Vec<Vec<u8>>,
    actual: Vec<u8>,
    digest: Digest,
}

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
    Inline(Vec<(usize, Vec<u8>)>),
}

impl PubSubState {
    pub(in crate::replay::redis) fn prepare_echo(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<Prepared> {
        if exchange.record.response_kind == "error"
            || exchange.record.outcome != DependencyExchangeOutcome::Response
        {
            return None;
        }
        self.is_adapter_source(exchange).then_some(())?;
        Some(Prepared {
            digest: rpc::echo_digest(&exchange.args[0], &exchange.args[1])?,
            source: exchange.args.clone(),
            actual: args.get(1)?.clone(),
        })
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
                                    .then(|| push.bytes().ok().map(|bytes| (index, bytes)))
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
                ensure!(
                    entries.len() == 1,
                    "ambiguous recorded adapter self-echo in subscription"
                );
                for (index, entry) in entries {
                    let reference: RecordRef = source.reference(entry.location.clone());
                    let raw = reference.load::<RecordedPush>()?.response.decode()?;
                    candidates.push((
                        PushId::Indexed {
                            lane: *lane,
                            index: *index,
                        },
                        render(&raw, prepared)?,
                    ));
                }
            }
        }
        JobInventory::Inline(pushes) => {
            for (index, raw) in pushes {
                let frame = parse_pubsub_push(raw)?.context("invalid adapter notification")?;
                if frame.channel == prepared.source[0] && frame.payload == prepared.source[1] {
                    candidates.push((PushId::Inline(*index), render(raw, prepared)?));
                }
            }
            ensure!(
                candidates.len() <= 1,
                "ambiguous recorded adapter self-echo in subscription"
            );
        }
    }
    Ok(candidates)
}

fn render(raw: &[u8], prepared: &Prepared) -> Result<Vec<u8>> {
    let push = parse_pubsub_push(raw)?.context("adapter echo is not a push")?;
    ensure!(
        push.channel == prepared.source[0] && push.payload == prepared.source[1],
        "adapter echo differs from its finite Source PUBLISH"
    );
    let frame = redis_command(&bytes::Bytes::copy_from_slice(raw))?;
    let mut parts = frame.args;
    *parts.last_mut().context("missing echo payload")? = prepared.actual.clone();
    let name = frame.name.to_ascii_lowercase();
    let mut values = vec![name.as_bytes()];
    values.extend(parts.iter().map(Vec::as_slice));
    Ok(crate::redis::encode_array(&values))
}

pub(in crate::replay::redis) async fn deliver(
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedRedisExchange,
) -> Result<()> {
    let Some(prepared) = &matched.adapter_echo else {
        return Ok(());
    };
    let jobs = {
        let replay = state.lock().await;
        replay.redis.pubsub.echo_jobs(matched, prepared)
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
        for (id, bytes) in candidates {
            ensure!(
                replay.redis.pubsub.is_subscribed(client, id),
                "adapter echo subscriber closed"
            );
            let available = match id {
                PushId::Inline(index) => replay.redis.pubsub.pushes[index].status.is_available(),
                PushId::Indexed { lane, index } => {
                    replay.redis.pubsub.indexed.available(lane, index)
                }
            };
            ensure!(available, "recorded adapter self-echo already claimed");
            match id {
                PushId::Inline(index) => {
                    replay.redis.pubsub.pushes[index].status = ReplayExchangeStatus::Responding
                }
                PushId::Indexed { lane, index } => {
                    replay.redis.pubsub.indexed.responding(lane, index)
                }
            }
            if sender
                .try_send(Delivery {
                    push: id,
                    bytes,
                    matched: None,
                })
                .is_err()
            {
                replay.redis.pubsub.fail(id);
                anyhow::bail!("adapter echo delivery queue unavailable");
            }
        }
    }
    Ok(())
}
