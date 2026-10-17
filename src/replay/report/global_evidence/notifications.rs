//! Versioned compact session evidence and lazy projection of optional Global pushes.
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shared::{SharedInventory, SharedReference};
use crate::dependency_index::{PageManifest, Paged, global::NotificationEntry};
use crate::replay::ReplaySource;
use crate::replay::redis::pubsub::{NotificationDelta, NotificationSessionEvidence};
use crate::replay::report::command::CommandUnusedReport;

const KIND: &str = "redis_global_compact_v1";
const SEMANTICS: &str = "global_unused_not_case_obligation";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedisEvidence {
    kind: String,
    pub pages: PageManifest,
    notifications: NotificationEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NotificationEvidence {
    semantics: String,
    inventory: SharedReference,
    recorded: usize,
    delivered: usize,
    failed: usize,
    remaining: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deltas: Vec<NotificationDelta>,
}

impl RedisEvidence {
    pub(super) fn prepare(
        report: &Path,
        pages: PageManifest,
        session: NotificationSessionEvidence,
    ) -> Result<Option<Self>> {
        Ok(
            NotificationEvidence::prepare(report, session)?.map(|notifications| Self {
                kind: KIND.into(),
                pages,
                notifications,
            }),
        )
    }
    pub(super) fn parse(value: &Value) -> Result<Option<Self>> {
        if value.get("kind").is_none() {
            return Ok(None);
        }
        let evidence: Self = serde_json::from_value(value.clone())?;
        ensure!(evidence.kind == KIND, "unsupported Global evidence format");
        Ok(Some(evidence))
    }
    pub(super) fn count(&self) -> Result<usize> {
        self.pages
            .count
            .checked_add(self.notifications.remaining)
            .context("Global detail count overflow")
    }
    pub(super) fn load(&self, report: &Path) -> Result<(SharedInventory, std::path::PathBuf)> {
        ensure!(self.kind == KIND, "unsupported Global evidence format");
        self.notifications.load(report)
    }
    pub(super) fn read_notifications(
        &self,
        report: &Path,
        offset: usize,
        limit: usize,
        items: &mut Vec<Value>,
    ) -> Result<()> {
        self.notifications.read(report, offset, limit, items)
    }
    pub(super) fn stage(&mut self, source: &Path, destination: &Path) -> Result<()> {
        self.load(source)?;
        self.pages.stage_into(
            source.parent().context("report has no parent")?,
            destination.parent().context("report has no parent")?,
        )?;
        self.notifications = self.notifications.stage(source, destination)?;
        Ok(())
    }
}
impl NotificationEvidence {
    pub(super) fn prepare(
        report: &Path,
        session: NotificationSessionEvidence,
    ) -> Result<Option<Self>> {
        if session.lanes.is_empty() {
            ensure!(
                session.recorded == 0 && session.delivered == 0 && session.failed == 0,
                "empty notification inventory has deliveries"
            );
            return Ok(None);
        }
        let evidence = Self {
            semantics: SEMANTICS.into(),
            inventory: super::shared::retain(report, &session.lanes)?,
            recorded: session.recorded,
            delivered: session.delivered,
            failed: session.failed,
            remaining: session
                .recorded
                .checked_sub(session.delivered)
                .context("notification count underflow")?,
            deltas: session.deltas,
        };
        evidence.load(report)?;
        Ok(Some(evidence))
    }
    pub(super) fn count(&self) -> usize {
        self.remaining
    }
    pub(super) fn load(&self, report: &Path) -> Result<(SharedInventory, std::path::PathBuf)> {
        ensure!(
            self.semantics == SEMANTICS,
            "unsupported Global notification semantics"
        );
        let (inventory, root) = self.inventory.load(report)?;
        let mut recorded = 0usize;
        let mut delivered = 0usize;
        let mut failed = 0usize;
        for lane in &inventory.lanes {
            recorded = recorded
                .checked_add(lane.pages.count)
                .context("notification count overflow")?;
        }
        let mut previous = None;
        for delta in &self.deltas {
            ensure!(
                previous.is_none_or(|lane| lane < delta.lane),
                "duplicate/unordered notification lane delta"
            );
            previous = Some(delta.lane);
            let lane = inventory
                .lanes
                .get(delta.lane)
                .context("notification delta lane is out of bounds")?;
            for positions in [&delta.consumed, &delta.failed, &delta.responding] {
                ensure!(
                    positions
                        .iter()
                        .all(|position| *position < lane.pages.count)
                        && positions.windows(2).all(|pair| pair[0] < pair[1]),
                    "invalid notification status positions"
                );
            }
            ensure!(
                delta
                    .consumed
                    .iter()
                    .all(|position| delta.failed.binary_search(position).is_err()
                        && delta.responding.binary_search(position).is_err())
                    && delta
                        .failed
                        .iter()
                        .all(|position| delta.responding.binary_search(position).is_err()),
                "conflicting notification statuses"
            );
            delivered = delivered
                .checked_add(delta.consumed.len())
                .context("notification count overflow")?;
            failed = failed
                .checked_add(delta.failed.len())
                .context("notification count overflow")?;
        }
        ensure!(
            recorded == self.recorded
                && delivered == self.delivered
                && failed == self.failed
                && recorded.checked_sub(delivered) == Some(self.remaining),
            "notification session counts do not match complete inventory and deltas"
        );
        Ok((inventory, root))
    }

    pub(super) fn read(
        &self,
        report: &Path,
        mut offset: usize,
        limit: usize,
        items: &mut Vec<Value>,
    ) -> Result<()> {
        let (inventory, root) = self.load(report)?;
        ensure!(
            offset <= self.remaining,
            "notification detail offset exceeds count"
        );
        if items.len() >= limit || offset == self.remaining {
            return Ok(());
        }
        for (lane_index, lane) in inventory.lanes.iter().enumerate() {
            let consumed = self
                .deltas
                .iter()
                .find(|delta| delta.lane == lane_index)
                .map(|delta| delta.consumed.as_slice())
                .unwrap_or_default();
            let remaining = lane.pages.count - consumed.len();
            if offset >= remaining {
                offset -= remaining;
                continue;
            }
            let pages = Paged::<NotificationEntry>::restore(lane.pages.clone().resolve(&root)?)?;
            // Map an unused ordinal to its physical position using only the
            // sparse consumed set; preceding source pages need not be opened.
            let mut position = offset;
            for index in consumed {
                if *index > position {
                    break;
                }
                position += 1;
            }
            for page in pages.page_for(position)?..pages.pages() {
                for (within, entry) in pages.read_page(page)?.into_iter().enumerate() {
                    let index = pages.page_start(page) + within;
                    if index < position || consumed.binary_search(&index).is_ok() {
                        continue;
                    }
                    ensure!(
                        entry.location.line > 0,
                        "notification source line is invalid"
                    );
                    items.push(serde_json::to_value(CommandUnusedReport {
                        index: entry.location.line - 1,
                        case_id: None,
                        source: ReplaySource::Global,
                        target: lane.identity.target.clone(),
                        connection_id: lane.identity.connection_id,
                        sequence: lane.identity.subscription_sequence,
                        command: "PUBSUB_PUSH".into(),
                    })?);
                    if items.len() == limit {
                        return Ok(());
                    }
                }
            }
            offset = 0;
        }
        Ok(())
    }

    pub(super) fn stage(&self, source: &Path, destination: &Path) -> Result<Self> {
        self.load(source)?;
        Ok(Self {
            inventory: self.inventory.stage(source, destination)?,
            ..self.clone()
        })
    }
}
