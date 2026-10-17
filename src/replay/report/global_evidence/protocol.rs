//! Compose native protocol inventory, optional Redis notifications and legacy pages.
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::notifications::{NotificationEvidence, RedisEvidence};
use super::regular::RegularEvidence;
use crate::dependency_index::{PageManifest, Paged};

const KIND: &str = "global_compact_v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProtocolEvidence {
    kind: String,
    protocol: String,
    regular: RegularEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notifications: Option<NotificationEvidence>,
}

impl ProtocolEvidence {
    pub(super) fn new(
        protocol: &str,
        regular: RegularEvidence,
        notifications: Option<NotificationEvidence>,
    ) -> Self {
        Self {
            kind: KIND.into(),
            protocol: protocol.into(),
            regular,
            notifications,
        }
    }

    fn parse(value: &Value) -> Result<Option<Self>> {
        if value["kind"] != KIND {
            return Ok(None);
        }
        Ok(Some(serde_json::from_value(value.clone())?))
    }

    fn validate(&self, report: &Path, protocol: &str) -> Result<()> {
        ensure!(
            self.kind == KIND
                && self.protocol == protocol
                && (protocol == "redis" || self.notifications.is_none()),
            "Global inventory protocol differs from its report section"
        );
        self.regular.validate_protocol(report, protocol)?;
        if let Some(notifications) = &self.notifications {
            notifications.load(report)?;
        }
        Ok(())
    }

    fn count(&self) -> Result<usize> {
        self.regular
            .count()?
            .checked_add(
                self.notifications
                    .as_ref()
                    .map_or(0, NotificationEvidence::count),
            )
            .context("Global detail count overflow")
    }
}

pub(super) enum NativeInventory {
    Pages(Paged<Value>),
    Redis {
        pages: Paged<Value>,
        evidence: RedisEvidence,
    },
    Shared(ProtocolEvidence),
}

impl NativeInventory {
    pub(super) fn open(report: &Path, protocol: &str, value: &Value) -> Result<Self> {
        if let Some(evidence) = ProtocolEvidence::parse(value)? {
            evidence.validate(report, protocol)?;
            return Ok(Self::Shared(evidence));
        }
        let root = report.parent().context("Global report has no parent")?;
        if let Some(evidence) = RedisEvidence::parse(value)? {
            ensure!(
                protocol == "redis",
                "compact Redis evidence used for another protocol"
            );
            evidence.load(report)?;
            let pages = Paged::restore(evidence.pages.clone().resolve(root)?)?;
            Ok(Self::Redis { pages, evidence })
        } else {
            let manifest: PageManifest = serde_json::from_value(value.clone()).context(
                "report lacks paginated Global evidence; use a fresh Replay on this engine",
            )?;
            Ok(Self::Pages(Paged::restore(manifest.resolve(root)?)?))
        }
    }

    pub(super) fn count(&self) -> Result<usize> {
        match self {
            Self::Pages(pages) => Ok(pages.count),
            Self::Redis { evidence, .. } => evidence.count(),
            Self::Shared(evidence) => evidence.count(),
        }
    }

    pub(super) fn read(
        &self,
        report: &Path,
        offset: usize,
        limit: usize,
        items: &mut Vec<Value>,
    ) -> Result<()> {
        match self {
            Self::Pages(pages) => read_pages(pages, offset, limit, items),
            Self::Redis { pages, evidence } => {
                read_pages(pages, offset, limit, items)?;
                if items.len() < limit && offset < evidence.count()? {
                    evidence.read_notifications(
                        report,
                        offset.saturating_sub(pages.count),
                        limit,
                        items,
                    )?;
                }
                Ok(())
            }
            Self::Shared(evidence) => {
                let regular = evidence.regular.count()?;
                if offset < regular {
                    evidence.regular.read(report, offset, limit, items)?;
                }
                if items.len() < limit
                    && offset < evidence.count()?
                    && let Some(notifications) = &evidence.notifications
                {
                    notifications.read(report, offset.saturating_sub(regular), limit, items)?;
                }
                Ok(())
            }
        }
    }
}

fn read_pages(
    pages: &Paged<Value>,
    offset: usize,
    limit: usize,
    items: &mut Vec<Value>,
) -> Result<()> {
    if offset >= pages.count || items.len() >= limit {
        return Ok(());
    }
    for page in pages.page_for(offset)?..pages.pages() {
        let start = pages.page_start(page);
        for (index, item) in pages.read_page(page)?.into_iter().enumerate() {
            if start + index < offset {
                continue;
            }
            items.push(item);
            if items.len() == limit {
                return Ok(());
            }
        }
    }
    Ok(())
}

pub(super) fn stage(
    value: &mut Value,
    protocol: &str,
    source: &Path,
    destination: &Path,
) -> Result<()> {
    if let Some(mut evidence) = ProtocolEvidence::parse(value)? {
        evidence.validate(source, protocol)?;
        evidence.regular = evidence.regular.stage(source, destination)?;
        evidence.notifications = evidence
            .notifications
            .as_ref()
            .map(|notifications| notifications.stage(source, destination))
            .transpose()?;
        *value = serde_json::to_value(evidence)?;
    } else if let Some(mut evidence) = RedisEvidence::parse(value)? {
        ensure!(
            protocol == "redis",
            "compact Redis evidence used for another protocol"
        );
        evidence.stage(source, destination)?;
        *value = serde_json::to_value(evidence)?;
    } else {
        serde_json::from_value::<PageManifest>(value.clone())?.stage_into(
            source.parent().context("report has no parent")?,
            destination.parent().context("report has no parent")?,
        )?;
    }
    Ok(())
}
