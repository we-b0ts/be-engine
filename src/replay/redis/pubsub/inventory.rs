//! Notification inventory pages retain locations, while each subscription shares its identity.
use super::*;
pub(super) use crate::dependency_index::global::NotificationEntry;
use crate::dependency_index::{PageWriter, Paged, RecordRef, RecordSource};
pub(in crate::replay) use evidence::{
    NotificationDelta, NotificationIdentity, NotificationLaneEvidence, NotificationSessionEvidence,
};
use std::path::Path;
mod evidence;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(super) struct IndexedLane {
    pub(super) record: RecordedPush,
    pub(super) kind: RedisSubscriptionKind,
    pub(super) subject: Vec<u8>,
    pub(super) source: Arc<RecordSource>,
    pub(super) pages: Option<Paged<NotificationEntry>>,
    writer: Option<PageWriter<NotificationEntry>>,
    count: usize,
    // Available is implicit. A notification costs session memory only after an
    // actual Target subscription attempts its delivery.
    statuses: BTreeMap<usize, ReplayExchangeStatus>,
    pub(super) echoes: Arc<std::sync::OnceLock<super::echo::EchoIndex>>,
}

#[derive(Debug, Default)]
pub(super) struct IndexedNotifications {
    pub(super) lanes: Vec<IndexedLane>,
    by_anchor: std::collections::HashMap<(Uuid, u64), usize>,
    pub(super) total: usize,
    pub(super) delivered: usize,
    pub(super) failed: usize,
}

impl IndexedNotifications {
    pub(super) fn restore(
        &mut self,
        lanes: Vec<crate::dependency_index::global::NotificationLane>,
        root: &Path,
        source: Arc<RecordSource>,
    ) -> Result<()> {
        ensure!(
            self.total == 0 && self.lanes.is_empty(),
            "notification inventory already initialized"
        );
        for lane in lanes {
            let record: RecordedPush = serde_json::from_value(lane.record)?;
            ensure!(
                record.replay_safe
                    && !record.response.truncated
                    && record.rpc_request.is_none()
                    && record.subscription_sequence > 0,
                "invalid indexed Redis notification metadata"
            );
            let kind = match lane.kind {
                0 => RedisSubscriptionKind::Channel,
                1 => RedisSubscriptionKind::Pattern,
                2 => RedisSubscriptionKind::ShardChannel,
                _ => anyhow::bail!("invalid indexed subscription kind"),
            };
            let pages = Paged::restore(lane.pages.resolve(root)?)?;
            let count = pages.count;
            let anchor = (record.connection_id, record.subscription_sequence);
            ensure!(
                self.by_anchor.insert(anchor, self.lanes.len()).is_none(),
                "duplicate indexed Redis subscription anchor"
            );
            self.lanes.push(IndexedLane {
                record,
                kind,
                subject: lane.subject,
                source: source.clone(),
                pages: Some(pages),
                writer: None,
                count,
                statuses: BTreeMap::new(),
                echoes: Arc::default(),
            });
            self.total += count;
        }
        Ok(())
    }
    pub(super) fn register(
        &mut self,
        mut record: RecordedPush,
        reference: RecordRef,
    ) -> Result<()> {
        ensure!(
            record.replay_safe && !record.response.truncated,
            "unsafe/truncated Redis Pub/Sub evidence"
        );
        ensure!(
            record.subscription_sequence > 0,
            "Pub/Sub subscription anchor missing"
        );
        let raw = record.response.decode()?;
        ensure!(
            raw.len() <= 64 * 1024 * 1024,
            "Redis Pub/Sub frame exceeds 64 MiB"
        );
        let frame = parse_pubsub_push(&raw)?.context("Redis Pub/Sub evidence is not a push")?;
        let key = (record.connection_id, record.subscription_sequence);
        let identity = (
            record.target_host.clone(),
            record.target_port,
            record.database,
            record.username.clone(),
        );
        let duration_ms = record.duration_ms;
        let timestamp = record.timestamp;
        let lane = match self.by_anchor.get(&key) {
            Some(index) => *index,
            None => {
                let index = self.lanes.len();
                record.response.data = String::new();
                record.duration_ms = 0;
                self.lanes.push(IndexedLane {
                    record,
                    kind: frame.subscription_kind,
                    subject: frame.subject.clone(),
                    source: reference.source.clone(),
                    pages: None,
                    writer: Some(PageWriter::new(reference.source.path())?),
                    count: 0,
                    statuses: BTreeMap::new(),
                    echoes: Arc::default(),
                });
                self.by_anchor.insert(key, index);
                index
            }
        };
        let lane = &mut self.lanes[lane];
        ensure!(
            lane.kind == frame.subscription_kind
                && lane.subject == frame.subject
                && (
                    lane.record.target_host.clone(),
                    lane.record.target_port,
                    lane.record.database,
                    lane.record.username.clone()
                ) == identity
                && lane.source.path() == reference.source.path(),
            "Redis Pub/Sub notification identity changed within its subscription"
        );
        lane.writer
            .as_mut()
            .context("notification inventory already sealed")?
            .push(NotificationEntry {
                adapter_namespace: rpc::notification_namespace(&frame.channel, &frame.payload),
                location: reference.location,
                duration_ms,
                timestamp,
                ordinal: self.total,
                adapter_echo: rpc::echo_digest(&frame.channel, &frame.payload),
                adapter_request: rpc::notification_request(&frame.channel, &frame.payload)
                    .map(|identity| (frame.channel, identity)),
            })?;
        lane.count += 1;
        self.total += 1;
        Ok(())
    }

    pub(super) fn seal(&mut self) -> Result<()> {
        for lane in &mut self.lanes {
            if let Some(writer) = lane.writer.take() {
                lane.pages = Some(writer.finish()?);
            }
            ensure!(
                lane.pages
                    .as_ref()
                    .is_some_and(|pages| pages.count == lane.count),
                "notification index count mismatch"
            );
        }
        Ok(())
    }

    pub(super) fn job(
        &self,
        connection: Uuid,
        sequence: u64,
    ) -> Option<(usize, Paged<NotificationEntry>, Arc<RecordSource>)> {
        let index = *self.by_anchor.get(&(connection, sequence))?;
        let lane = &self.lanes[index];
        Some((index, lane.pages.clone()?, lane.source.clone()))
    }

    pub(super) fn available(&self, lane: usize, index: usize) -> bool {
        let lane = &self.lanes[lane];
        assert!(index < lane.count);
        lane.statuses
            .get(&index)
            .is_none_or(|status| status.is_available())
    }
    pub(super) fn responding(&mut self, lane: usize, index: usize) {
        assert!(index < self.lanes[lane].count);
        self.lanes[lane]
            .statuses
            .insert(index, ReplayExchangeStatus::Responding);
    }
    pub(super) fn complete(&mut self, lane: usize, index: usize) {
        assert!(index < self.lanes[lane].count);
        let status = self.lanes[lane]
            .statuses
            .insert(index, ReplayExchangeStatus::Consumed);
        if status == Some(ReplayExchangeStatus::Consumed) {
            return;
        }
        if status == Some(ReplayExchangeStatus::Failed) {
            self.failed -= 1;
        }
        self.delivered += 1;
    }
    pub(super) fn fail(&mut self, lane: usize, index: usize) {
        assert!(index < self.lanes[lane].count);
        let status = self.lanes[lane].statuses.get(&index);
        if matches!(
            status,
            Some(ReplayExchangeStatus::Consumed | ReplayExchangeStatus::Failed)
        ) {
            return;
        }
        self.lanes[lane]
            .statuses
            .insert(index, ReplayExchangeStatus::Failed);
        self.failed += 1;
    }

    pub(super) fn unused(&self, limit: usize) -> Vec<CommandUnusedReport> {
        let mut result = Vec::new();
        for lane in &self.lanes {
            let Some(pages) = &lane.pages else {
                continue;
            };
            let mut loaded_page = None;
            let mut entries = Vec::new();
            for index in 0..lane.count {
                if lane.statuses.get(&index) == Some(&ReplayExchangeStatus::Consumed) {
                    continue;
                }
                if result.len() >= limit {
                    return result;
                }
                let Ok(page) = pages.page_for(index) else {
                    return result;
                };
                if loaded_page != Some(page) {
                    let Ok(next) = pages.read_page(page) else {
                        return result;
                    };
                    entries = next;
                    loaded_page = Some(page);
                }
                result.push(CommandUnusedReport {
                    index: entries[index - pages.page_start(page)].location.line - 1,
                    case_id: None,
                    source: ReplaySource::Global,
                    target: TargetKey {
                        host: normalize_host(&lane.record.target_host),
                        port: lane.record.target_port,
                    },
                    connection_id: lane.record.connection_id,
                    sequence: lane.record.subscription_sequence,
                    command: "PUBSUB_PUSH".into(),
                });
            }
        }
        result
    }
}
