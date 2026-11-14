//! Shared Global inventories compose ordinary rows and registered evidence sections.
use super::regular::RegularEvidence;
use crate::dependency_index::{PageManifest, Paged};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};
use traffic_protocol::report::{ReportCodec, ReportSection};
const KIND: &str = "global_compact_v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ProtocolEvidence {
    kind: String,
    protocol: String,
    regular: RegularEvidence,
    #[serde(flatten)]
    extensions: BTreeMap<String, Value>,
}
impl ProtocolEvidence {
    pub(super) fn new(
        protocol: &str,
        regular: RegularEvidence,
        extensions: BTreeMap<String, Value>,
    ) -> Self {
        Self {
            kind: KIND.into(),
            protocol: protocol.into(),
            regular,
            extensions,
        }
    }
    fn parse(value: &Value) -> Result<Option<Self>> {
        if value["kind"] != KIND {
            return Ok(None);
        }
        Ok(Some(serde_json::from_value(value.clone())?))
    }
    fn validate(
        &self,
        report: &Path,
        protocol: &str,
        codec: Option<&dyn ReportCodec>,
    ) -> Result<Option<Box<dyn ReportSection>>> {
        ensure!(
            self.kind == KIND && self.protocol == protocol,
            "Global inventory protocol differs from its report section"
        );
        self.regular.validate_protocol(report, protocol)?;
        if self.extensions.is_empty() {
            return Ok(None);
        }
        let codec = codec.context("Global inventory has no registered extension codec")?;
        Ok(Some(codec.decode_extensions(report, &self.extensions)?))
    }
}

pub(super) enum NativeInventory {
    Pages(Paged<Value>),
    Native(Box<dyn ReportSection>),
    Shared {
        evidence: ProtocolEvidence,
        extension: Option<Box<dyn ReportSection>>,
    },
}
impl NativeInventory {
    pub(super) fn open(report: &Path, protocol: &str, value: &Value) -> Result<Self> {
        let providers = crate::protocols::default_providers();
        let codec = providers.report_codec(protocol);
        Self::open_with_codec(report, protocol, value, codec.as_deref())
    }
    pub(super) fn open_with_codec(
        report: &Path,
        protocol: &str,
        value: &Value,
        codec: Option<&dyn ReportCodec>,
    ) -> Result<Self> {
        if let Some(evidence) = ProtocolEvidence::parse(value)? {
            let extension = evidence.validate(report, protocol, codec)?;
            return Ok(Self::Shared {
                evidence,
                extension,
            });
        }
        if let Some(codec) = codec
            && let Some(section) = codec.decode(report, value)?
        {
            return Ok(Self::Native(section));
        }
        ensure!(
            value.get("kind").is_none(),
            "unsupported Global evidence format"
        );
        let root = report.parent().context("Global report has no parent")?;
        let manifest: PageManifest = serde_json::from_value(value.clone())
            .context("report lacks paginated Global evidence; use a fresh Replay on this engine")?;
        Ok(Self::Pages(Paged::restore(manifest.resolve(root)?)?))
    }
    pub(super) fn count(&self) -> Result<usize> {
        match self {
            Self::Pages(pages) => Ok(pages.count),
            Self::Native(section) => section.count(),
            Self::Shared {
                evidence,
                extension,
            } => evidence
                .regular
                .count()?
                .checked_add(
                    extension
                        .as_ref()
                        .map_or(Ok(0), |section| section.count())?,
                )
                .context("Global detail count overflow"),
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
            Self::Pages(pages) => pages.read_into(offset, limit, items),
            Self::Native(section) => section.read(report, offset, limit, items),
            Self::Shared {
                evidence,
                extension,
            } => {
                let regular = evidence.regular.count()?;
                if offset < regular {
                    evidence.regular.read(report, offset, limit, items)?;
                }
                if items.len() < limit
                    && offset < self.count()?
                    && let Some(section) = extension
                {
                    section.read(report, offset.saturating_sub(regular), limit, items)?;
                }
                Ok(())
            }
        }
    }
}
pub(super) fn stage(
    value: &mut Value,
    protocol: &str,
    source: &Path,
    destination: &Path,
) -> Result<()> {
    let providers = crate::protocols::default_providers();
    let codec = providers.report_codec(protocol);
    if let Some(mut evidence) = ProtocolEvidence::parse(value)? {
        let extension = evidence.validate(source, protocol, codec.as_deref())?;
        evidence.regular = evidence.regular.stage(source, destination)?;
        if let Some(section) = extension {
            evidence.extensions = serde_json::from_value(section.stage(source, destination)?)?;
            ensure!(
                evidence
                    .extensions
                    .keys()
                    .all(|key| !matches!(key.as_str(), "kind" | "protocol" | "regular")),
                "native evidence overlaps shared inventory fields"
            );
        }
        evidence.validate(destination, protocol, codec.as_deref())?;
        *value = serde_json::to_value(evidence)?;
    } else if let Some(codec) = codec
        && let Some(section) = codec.decode(source, value)?
    {
        *value = section.stage(source, destination)?;
    } else {
        ensure!(
            value.get("kind").is_none(),
            "unsupported Global evidence format"
        );
        serde_json::from_value::<PageManifest>(value.clone())?.stage_into(
            source.parent().context("report has no parent")?,
            destination.parent().context("report has no parent")?,
        )?;
    }
    Ok(())
}
