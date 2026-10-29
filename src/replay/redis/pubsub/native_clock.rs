//! Finite external ordinary Socket.IO inputs follow a passive native request clock.
use super::*;
use crate::{dependency_index::RecordRef, replay::ReplayCase};
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet};

mod driver;
mod preparation;
mod source;
pub(in crate::replay) use driver::start;

#[derive(Debug, Default)]
pub(in crate::replay) struct NativeClock {
    namespaces: BTreeSet<String>,
    entries: Vec<Entry>,
    live: BTreeMap<String, Live>,
}

#[derive(Debug)]
struct Live {
    epoch: DateTime<Utc>,
    observer: bool,
    closed: bool,
    namespaces: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct Entry {
    case: String,
    namespace: String,
    slot: PushId,
    anchor: (Uuid, u64),
    reference: Option<RecordRef>,
    inline: Vec<u8>,
    source_at: DateTime<Utc>,
    offset: chrono::TimeDelta,
    ordinal: usize,
    digest: [u8; 32],
    endpoint: TargetKey,
    database: i64,
    username: Option<String>,
    lifetime: chrono::TimeDelta,
    reserved: bool,
}

impl Entry {
    fn bytes(&self) -> Result<Vec<u8>> {
        match &self.reference {
            Some(reference) => {
                let record = reference.load::<RecordedPush>()?;
                ensure!(
                    (record.connection_id, record.subscription_sequence) == self.anchor
                        && record.timestamp == Some(self.source_at)
                        && endpoint(&record) == self.endpoint
                        && record.database == self.database
                        && record.username == self.username,
                    "native notification metadata changed"
                );
                record.response.decode()
            }
            None => Ok(self.inline.clone()),
        }
    }
}

fn endpoint(record: &RecordedPush) -> TargetKey {
    TargetKey {
        host: normalize_host(&record.target_host),
        port: record.target_port,
    }
}

impl NativeClock {
    pub(in crate::replay) fn needs_observer(&self, case: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.case == case && !entry.reserved)
    }
    pub(in crate::replay) fn epoch(&self, case: &str) -> Option<DateTime<Utc>> {
        self.live.get(case).map(|live| live.epoch)
    }
    pub(in crate::replay) fn begin_case(&mut self, case: &str) {
        self.live.remove(case);
    }
    pub(in crate::replay) fn close_case(&mut self, case: &str) {
        if let Some(live) = self.live.get_mut(case) {
            live.closed = true;
            live.observer = false;
        }
    }
    pub(in crate::replay) fn request_begin(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
    ) -> Result<()> {
        ensure!(
            !self.live.contains_key(case),
            "native notification request already admitted"
        );
        if !self.needs_observer(case) {
            return Ok(());
        }
        self.live.insert(
            case.into(),
            Live {
                epoch,
                observer: false,
                closed: false,
                namespaces: BTreeSet::new(),
            },
        );
        Ok(())
    }
    pub(super) fn observe_begin(&mut self, case: &str, epoch: DateTime<Utc>) -> Result<()> {
        if !self.needs_observer(case) {
            return Ok(());
        }
        let live = self
            .live
            .get_mut(case)
            .context("native notification request not admitted")?;
        ensure!(
            live.epoch == epoch && !live.closed,
            "native notification request epoch changed"
        );
        live.observer = true;
        Ok(())
    }
    pub(in crate::replay) fn connected(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        namespace: &str,
    ) -> Result<()> {
        ensure!(
            !namespace.is_empty() && namespace.len() <= 1024,
            "invalid native namespace metadata"
        );
        if !self.needs_observer(case) {
            return Ok(());
        }
        let live = self
            .live
            .get_mut(case)
            .context("native notification request not admitted")?;
        ensure!(
            live.observer && !live.closed && live.epoch == epoch,
            "native namespace observer epoch changed"
        );
        ensure!(
            self.entries
                .iter()
                .any(|entry| entry.case == case && entry.namespace == namespace),
            "native namespace is outside original input scope"
        );
        live.namespaces.insert(namespace.into());
        Ok(())
    }
    pub(super) fn guards(&self, namespace: Option<&str>) -> bool {
        namespace.is_some_and(|namespace| self.namespaces.contains(namespace))
    }
}
