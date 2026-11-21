//! Finite adapter self-echo proofs over original PUBLISH and notification bytes.
use crate::recorded::{RecordedExchange, RecordedPush};
use crate::{RedisSubscriptionKind, parse_pubsub_push, redis_command, socketio_rpc as rpc};
use anyhow::{Context, Result, anyhow, ensure};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;
use traffic_model::DependencyExchangeOutcome;
use traffic_protocol::{connection::Endpoint, observation::normalize_host};
use uuid::Uuid;
mod window;

pub type Digest = [u8; 32];
fn endpoint(record: &RecordedPush) -> Endpoint {
    Endpoint {
        host: normalize_host(&record.target_host),
        port: record.target_port,
    }
}
type PublisherKey = (Endpoint, Digest);
type Publications = HashMap<PublisherKey, BTreeMap<window::WireIdentity, window::Publication>>;
type Windows = HashMap<
    PublisherKey,
    std::result::Result<BTreeMap<window::WireIdentity, window::Bounds>, String>,
>;

#[derive(Debug, Default)]
pub struct Echoes {
    publishers: Publications,
    channels: HashSet<(Endpoint, Vec<u8>)>,
    windows: OnceLock<Windows>,
}
impl Echoes {
    pub fn register(&mut self, record: &RecordedExchange, args: &[Vec<u8>]) {
        if args.len() != 2 {
            return;
        }
        if let Some(digest) = rpc::echo_digest(&args[0], &args[1]) {
            let target = Endpoint {
                host: normalize_host(&record.target_host),
                port: record.target_port,
            };
            let publishers = self.publishers.entry((target.clone(), digest)).or_default();
            if let std::collections::btree_map::Entry::Vacant(entry) =
                publishers.entry((record.connection_id, record.sequence))
            {
                entry.insert(window::Publication::from_record(record));
                self.windows.take();
            }
            self.channels.insert((target, args[0].clone()));
        }
    }
    pub fn prepare_windows(&self) {
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
        target: &Endpoint,
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
            .get(&(record.connection_id, record.sequence))
            .cloned()
            .ok_or_else(|| "Source publisher missing from immutable echo inventory".into())
    }
    pub fn controls(&self, record: &RecordedPush, digest: Option<Digest>) -> bool {
        digest.is_some_and(|digest| self.publishers.contains_key(&(endpoint(record), digest)))
    }
}

#[derive(Debug, Clone)]
pub struct Prepared {
    pub source: Vec<Vec<u8>>,
    actual: Vec<u8>,
    pub digest: Digest,
    window: std::result::Result<window::Bounds, String>,
    repeated_publication: bool,
}

impl Echoes {
    pub fn prepare(
        &self,
        record: &RecordedExchange,
        source: &[Vec<u8>],
        args: &[Vec<u8>],
    ) -> Option<Prepared> {
        if source.len() != 2 {
            return None;
        }
        if record.response_kind == "error" || record.outcome != DependencyExchangeOutcome::Response
        {
            return None;
        }
        let digest = rpc::echo_digest(&source[0], &source[1])?;
        let target = Endpoint {
            host: normalize_host(&record.target_host),
            port: record.target_port,
        };
        let publications = self.publishers.get(&(target.clone(), digest))?;
        Some(Prepared {
            digest,
            window: self.window(&target, digest, record),
            repeated_publication: publications.len() > 1,
            source: source.to_vec(),
            actual: args.get(1)?.clone(),
        })
    }
}
impl Echoes {
    pub fn needs_index(
        &self,
        record: &RecordedPush,
        kind: RedisSubscriptionKind,
        subject: &[u8],
    ) -> bool {
        kind != RedisSubscriptionKind::ShardChannel
            && self.channels.iter().any(|(target, channel)| {
                *target == endpoint(record)
                    && (kind == RedisSubscriptionKind::Pattern || channel.as_slice() == subject)
            })
    }
}

impl Prepared {
    pub fn select(
        &self,
        entries: impl Iterator<Item = (usize, Option<chrono::DateTime<chrono::Utc>>)>,
    ) -> Result<Vec<usize>> {
        let entries = entries.collect::<Vec<_>>();
        if entries.len() <= 1 && !self.repeated_publication {
            return Ok(entries.into_iter().map(|(index, _)| index).collect());
        }
        let window = self
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

    pub fn render(&self, raw: &[u8]) -> Result<Vec<u8>> {
        let push = parse_pubsub_push(raw)?.context("adapter echo is not a push")?;
        ensure!(
            push.channel == self.source[0] && push.payload == self.source[1],
            "adapter echo differs from its finite Source PUBLISH"
        );
        let frame = redis_command(&bytes::Bytes::copy_from_slice(raw))?;
        let mut parts = frame.args;
        *parts.last_mut().context("missing echo payload")? = self.actual.clone();
        let name = frame.name.to_ascii_lowercase();
        let mut values = vec![name.as_bytes()];
        values.extend(parts.iter().map(Vec::as_slice));
        Ok(crate::encode_array(&values))
    }
}
