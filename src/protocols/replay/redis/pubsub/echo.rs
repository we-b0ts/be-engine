//! Finite Socket.IO adapter self-echoes follow admitted PUBLISH calls, not subscription age.
use super::*;
use crate::dependency_index::RecordRef;
use inventory::NotificationEntry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;
mod preparation;
mod window;

type Digest = [u8; 32];
fn endpoint(record: &RecordedPush) -> TargetKey {
    TargetKey {
        host: normalize_host(&record.target_host),
        port: record.target_port,
    }
}
pub(super) type EchoIndex =
    std::result::Result<BTreeMap<Digest, Vec<(usize, NotificationEntry)>>, String>;

type PublisherKey = (TargetKey, Digest);
type Publications = HashMap<PublisherKey, BTreeMap<window::WireIdentity, window::Publication>>;
type Windows = HashMap<
    PublisherKey,
    std::result::Result<BTreeMap<window::WireIdentity, window::Bounds>, String>,
>;
type InlineEcho = (usize, Option<chrono::DateTime<chrono::Utc>>, Vec<u8>);

#[derive(Debug, Default)]
pub(super) struct Echoes {
    publishers: Publications,
    channels: HashSet<(TargetKey, Vec<u8>)>,
    windows: OnceLock<Windows>,
}
impl Echoes {
    pub(super) fn register(&mut self, record: &RecordedExchange, args: &[Vec<u8>]) {
        if let Some(digest) = rpc::echo_digest(&args[0], &args[1]) {
            let target = TargetKey {
                host: normalize_host(&record.native.target_host),
                port: record.native.target_port,
            };
            let publishers = self.publishers.entry((target.clone(), digest)).or_default();
            if let std::collections::btree_map::Entry::Vacant(entry) =
                publishers.entry((record.native.connection_id, record.native.sequence))
            {
                entry.insert(window::Publication::from_record(record));
                self.windows.take();
            }
            self.channels.insert((target, args[0].clone()));
        }
    }
    pub(super) fn prepare_windows(&self) {
        self.windows.get_or_init(|| {
            self.publishers
                .iter()
                .map(|(key, publishers)| {
                    (
                        key.clone(),
                        window::Bounds::all(publishers).map_err(|error| format!("{error:#}")),
                    )
                })
                .collect()
        });
    }
    fn window(
        &self,
        target: &TargetKey,
        digest: Digest,
        record: &RecordedExchange,
    ) -> std::result::Result<window::Bounds, String> {
        self.windows
            .get()
            .ok_or("Source publication windows were not prepared")?
            .get(&(target.clone(), digest))
            .ok_or("Source publisher has no echo inventory")?
            .as_ref()
            .map_err(Clone::clone)?
            .get(&(record.native.connection_id, record.native.sequence))
            .cloned()
            .ok_or_else(|| "Source publisher missing from immutable echo inventory".into())
    }
    pub(super) fn controls(&self, record: &RecordedPush, digest: Option<Digest>) -> bool {
        digest.is_some_and(|digest| self.publishers.contains_key(&(endpoint(record), digest)))
    }
}

#[derive(Debug, Clone)]
pub(in crate::protocols::replay::redis) struct Prepared {
    source: Vec<Vec<u8>>,
    actual: Vec<u8>,
    digest: Digest,
    window: std::result::Result<window::Bounds, String>,
    repeated_publication: bool,
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
    Inline(Vec<InlineEcho>),
}

impl PubSubState {
    pub(in crate::protocols::replay::redis) fn prepare_echo(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<Prepared> {
        if exchange.record.native.response_kind == "error"
            || exchange.record.native.outcome != DependencyExchangeOutcome::Response
        {
            return None;
        }
        self.is_adapter_source(exchange).then_some(())?;
        let digest = rpc::echo_digest(&exchange.args[0], &exchange.args[1])?;
        let target = TargetKey {
            host: normalize_host(&exchange.record.native.target_host),
            port: exchange.record.native.target_port,
        };
        let publications = self.echoes.publishers.get(&(target.clone(), digest))?;
        Some(Prepared {
            digest,
            window: self.echoes.window(&target, digest, &exchange.record),
            repeated_publication: publications.len() > 1,
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
                let selected = select(
                    entries
                        .iter()
                        .map(|(index, entry)| (*index, entry.timestamp)),
                    prepared,
                )?;
                for (index, entry) in entries.iter().filter(|(index, _)| selected.contains(index)) {
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
            let mut echoes = Vec::new();
            for (index, timestamp, raw) in pushes {
                let frame = parse_pubsub_push(raw)?.context("invalid adapter notification")?;
                if frame.channel == prepared.source[0] && frame.payload == prepared.source[1] {
                    echoes.push((*index, *timestamp, raw));
                }
            }
            let selected = select(
                echoes
                    .iter()
                    .map(|(index, timestamp, _)| (*index, *timestamp)),
                prepared,
            )?;
            for (index, _, raw) in echoes
                .into_iter()
                .filter(|(index, _, _)| selected.contains(index))
            {
                candidates.push((PushId::Inline(index), render(raw, prepared)?));
            }
        }
    }
    Ok(candidates)
}

fn select(
    entries: impl Iterator<Item = (usize, Option<chrono::DateTime<chrono::Utc>>)>,
    prepared: &Prepared,
) -> Result<Vec<usize>> {
    let entries = entries.collect::<Vec<_>>();
    if entries.len() <= 1 && !prepared.repeated_publication {
        return Ok(entries.into_iter().map(|(index, _)| index).collect());
    }
    let window = prepared
        .window
        .as_ref()
        .map_err(|error| anyhow!("ambiguous recorded adapter self-echo: {error}"))?;
    let mut selected = Vec::new();
    for (index, timestamp) in entries {
        let timestamp = timestamp
            .context("ambiguous recorded adapter self-echo lacks Source notification clock")?;
        if window.contains(timestamp) {
            selected.push(index);
        }
    }
    ensure!(
        selected.len() <= 1,
        "ambiguous recorded adapter self-echo in Source publication interval"
    );
    Ok(selected)
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
