//! Exact confirmed subscription proofs share the original finite command slot.
use super::*;
use crate::dependency_index::{RecordReader, load_file, recording_files};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex as StdMutex;

type Anchor = (Uuid, u64);

struct Requirement {
    host: String,
    port: u16,
    database: i64,
    username: Option<String>,
    kind: RedisSubscriptionKind,
    subject: Vec<u8>,
    global: bool,
}

impl Requirement {
    fn command(&self) -> &'static str {
        match self.kind {
            RedisSubscriptionKind::Channel => "SUBSCRIBE",
            RedisSubscriptionKind::Pattern => "PSUBSCRIBE",
            RedisSubscriptionKind::ShardChannel => "SSUBSCRIBE",
        }
    }

    fn validate(&self, record: &RecordedExchange) -> Result<()> {
        let args = validate_confirmation(record)?;
        ensure!(
            record.command == self.command()
                && args.first() == Some(&self.subject)
                && normalize_host(&record.target_host) == self.host
                && record.target_port == self.port
                && record.database == self.database
                && record.username == self.username,
            "Redis Pub/Sub push does not match its recorded subscription"
        );
        Ok(())
    }

    fn missing(&self, anchor: Anchor) -> anyhow::Error {
        anyhow!(
            "Redis Pub/Sub subscription evidence missing from recording: connection {}, sequence {}, target {}:{}; refresh the recording with its confirmed subscription",
            anchor.0,
            anchor.1,
            self.host,
            self.port
        )
    }
}

impl PubSubState {
    pub(in crate::replay) fn retain_subscription_mirror(
        &mut self,
        record: RecordedExchange,
    ) -> Result<()> {
        validate_confirmation(&record)?;
        ensure!(
            self.subscription_mirrors
                .insert((record.connection_id, record.sequence), record)
                .is_none(),
            "ambiguous recorded Redis subscription mirror identity"
        );
        Ok(())
    }

    fn requirements(&self) -> Result<BTreeMap<Anchor, Requirement>> {
        let mut requirements: BTreeMap<Anchor, Requirement> = BTreeMap::new();
        for (record, kind, subject, global) in self
            .pushes
            .iter()
            .map(|p| {
                (
                    &p.record,
                    p.kind,
                    &p.subject,
                    p.source == ReplaySource::Global,
                )
            })
            .chain(
                self.indexed
                    .lanes
                    .iter()
                    .map(|lane| (&lane.record, lane.kind, &lane.subject, true)),
            )
        {
            let anchor = (record.connection_id, record.subscription_sequence);
            if let Some(previous) = requirements.get_mut(&anchor) {
                ensure!(
                    previous.host == normalize_host(&record.target_host)
                        && previous.port == record.target_port
                        && previous.database == record.database
                        && previous.username == record.username
                        && previous.kind == kind
                        && previous.subject == *subject,
                    "inconsistent Redis Pub/Sub subscription anchor identity"
                );
                previous.global |= global;
            } else {
                requirements.insert(
                    anchor,
                    Requirement {
                        host: normalize_host(&record.target_host),
                        port: record.target_port,
                        database: record.database,
                        username: record.username.clone(),
                        kind,
                        subject: subject.clone(),
                        global,
                    },
                );
            }
        }
        Ok(requirements)
    }

    pub(in crate::replay::redis) fn validate_subscriptions(
        &self,
        exchanges: &[ReplayExchange],
    ) -> Result<()> {
        let subscriptions = loaded_subscriptions(exchanges)?;
        for (anchor, requirement) in self.requirements()? {
            let (_, record) = subscriptions
                .get(&anchor)
                .ok_or_else(|| requirement.missing(anchor))?;
            requirement.validate(record)?;
        }
        Ok(())
    }
}

impl RedisReplayState {
    pub(in crate::replay) fn resolve_pubsub_subscriptions(
        &mut self,
        root: &Path,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
        rules: &[crate::BackgroundDependencyRuleConfig],
        reader: Arc<StdMutex<RecordReader>>,
    ) -> Result<()> {
        let requirements = self.pubsub.requirements()?;
        let mut subscriptions = loaded_subscriptions(&self.exchanges)?;
        // The mirror is a proof, never a second replayable command. Preserve the
        // original selected Case slot, ownership, lane barriers and consumption.
        for (anchor, mirror) in &self.pubsub.subscription_mirrors {
            if let Some((_, original)) = subscriptions.get(anchor) {
                ensure_same_subscription(original, mirror)?;
            }
        }
        let mut missing = BTreeMap::new();
        for (anchor, requirement) in &requirements {
            if let Some((_, record)) = subscriptions.get(anchor) {
                requirement.validate(record)?;
            } else if let Some(mirror) = self.pubsub.subscription_mirrors.get(anchor) {
                requirement.validate(mirror)?;
            } else {
                missing.insert(*anchor, requirement);
            }
        }
        let foreign = find_subscriptions(root, &missing, reader)?;
        for (anchor, requirement) in requirements {
            let has_mirror = self.pubsub.subscription_mirrors.contains_key(&anchor);
            let global_alias = requirement.global || has_mirror;
            if let Some((index, _)) = subscriptions.get(&anchor) {
                self.exchanges[*index].subscription_alias |= global_alias;
                continue;
            }
            let record = self
                .pubsub
                .subscription_mirrors
                .get(&anchor)
                .or_else(|| foreign.get(&anchor))
                .ok_or_else(|| requirement.missing(anchor))?
                .clone();
            requirement.validate(&record)?;
            ensure!(
                global_alias,
                "Redis Pub/Sub Case callback subscription is outside the selected command inventory"
            );
            let index = self.exchanges.len();
            self.register_exchange(record.clone(), ReplaySource::Global, None, targets, rules)?;
            subscriptions.insert(anchor, (index, record));
        }
        self.pubsub.subscription_mirrors.clear();
        self.validate_pubsub()
    }
}

fn validate_confirmation(record: &RecordedExchange) -> Result<Vec<Vec<u8>>> {
    ensure!(
        matches!(
            record.command.as_str(),
            "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE"
        ) && record.outcome == DependencyExchangeOutcome::Response
            && record.response_kind == "array",
        "Redis Pub/Sub subscription evidence lacks a successful confirmation"
    );
    validate_recorded_exchange(
        "redis_exchange",
        &record.command,
        record.replay_safe,
        record.response.truncated || record.args.iter().any(|arg| arg.truncated),
    )?;
    let args = record
        .args
        .iter()
        .map(RecordedCapture::decode)
        .collect::<Result<Vec<_>>>()?;
    validate_subscription_exchange(record, &args, &record.response.decode()?)?;
    Ok(args)
}

fn loaded_subscriptions(
    exchanges: &[ReplayExchange],
) -> Result<BTreeMap<Anchor, (usize, RecordedExchange)>> {
    let mut records = BTreeMap::new();
    for (index, exchange) in exchanges.iter().enumerate().filter(|(_, e)| {
        matches!(
            e.record.command.as_str(),
            "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE"
        ) && e.record.response_kind != "error"
            && e.record.outcome == DependencyExchangeOutcome::Response
    }) {
        let mut record = exchange.record.clone();
        record.response = RecordedCapture {
            encoding: "base64".into(),
            data: STANDARD.encode(exchange.response_bytes()?),
            truncated: false,
        };
        validate_confirmation(&record)?;
        ensure!(
            records
                .insert((record.connection_id, record.sequence), (index, record))
                .is_none(),
            "ambiguous recorded Redis subscription identity"
        );
    }
    Ok(records)
}

fn ensure_same_subscription(original: &RecordedExchange, mirror: &RecordedExchange) -> Result<()> {
    fn normalized(record: &RecordedExchange) -> Result<serde_json::Value> {
        let mut record = record.clone();
        record.global_dependency_reason = None;
        for capture in record.args.iter_mut().chain([&mut record.response]) {
            capture.data = STANDARD.encode(capture.decode()?);
            capture.encoding = "base64".into();
        }
        Ok(serde_json::to_value(record)?)
    }
    ensure!(
        original.id == mirror.id && normalized(original)? == normalized(mirror)?,
        "Redis Pub/Sub subscription mirror conflicts with its original command evidence"
    );
    Ok(())
}

fn find_subscriptions(
    source: &Path,
    required: &BTreeMap<Anchor, &Requirement>,
    reader: Arc<StdMutex<RecordReader>>,
) -> Result<BTreeMap<Anchor, RecordedExchange>> {
    if required.is_empty() {
        return Ok(BTreeMap::new());
    }
    let (_, files) = recording_files(source).map_err(|error| {
        let (&anchor, requirement) = required.first_key_value().expect("missing subscription");
        requirement.missing(anchor).context(error)
    })?;
    let connections: BTreeSet<_> = required.keys().map(|anchor| anchor.0.to_string()).collect();
    let mut records = BTreeMap::new();
    for file in files {
        let index = load_file(&file)?;
        let mut candidates = BTreeMap::new();
        let mut blockers: BTreeMap<Anchor, (u64, String)> = BTreeMap::new();
        for entry in index.redis.iter().filter(|entry| {
            entry
                .connection_id
                .as_ref()
                .is_some_and(|connection| connections.contains(connection))
        }) {
            let raw = reader
                .lock()
                .map_err(|_| anyhow!("dependency cache lock poisoned"))?
                .read(&file, &index.stamp, &entry.location)?;
            let value: serde_json::Value = serde_json::from_slice(&raw)?;
            if value["event_type"] != "redis_exchange" {
                continue;
            }
            let record: RecordedExchange = serde_json::from_value(value)?;
            let anchor = (record.connection_id, record.sequence);
            if let Some(requirement) = required.get(&anchor) {
                requirement.validate(&record)?;
                ensure!(
                    candidates.insert(anchor, record.clone()).is_none(),
                    "ambiguous recorded Redis subscription identity across Cases"
                );
            }
            if !is_filtered_session_setup(&record)? {
                for &required_anchor in required.keys().filter(|required_anchor| {
                    required_anchor.0 == record.connection_id && record.sequence < required_anchor.1
                }) {
                    blockers
                        .entry(required_anchor)
                        .or_insert((record.sequence, record.command.clone()));
                }
            }
        }
        for (anchor, record) in candidates {
            if let Some((sequence, command)) = blockers.get(&anchor) {
                anyhow::bail!(
                    "Redis Pub/Sub subscription evidence cannot be imported across Cases without its recorded lane predecessor: connection {}, subscription sequence {}, predecessor sequence {} command {}; refresh the recording with a startup subscription",
                    anchor.0,
                    anchor.1,
                    sequence,
                    command
                );
            }
            ensure!(
                records.insert(anchor, record).is_none(),
                "ambiguous recorded Redis subscription identity across Cases"
            );
        }
    }
    Ok(records)
}

fn is_filtered_session_setup(record: &RecordedExchange) -> Result<bool> {
    if !matches!(
        record.command.as_str(),
        "AUTH" | "HELLO" | "SELECT" | "CLIENT" | "PING"
    ) {
        return Ok(false);
    }
    let args = record
        .args
        .iter()
        .map(RecordedCapture::decode)
        .collect::<Result<Vec<_>>>()?;
    if record.outcome != DependencyExchangeOutcome::Response
        || !record.replay_safe
        || record.response.truncated
    {
        return Ok(false);
    }
    record.response.decode()?;
    if crate::redis::is_client_library_info(&record.command, &args) {
        return Ok(true);
    }
    let command = RedisCommand {
        name: record.command.clone(),
        args,
    };
    Ok(record.response_kind != "error"
        && redis_builtin(&command, &mut 2, &mut 0, &mut None).is_some())
}
