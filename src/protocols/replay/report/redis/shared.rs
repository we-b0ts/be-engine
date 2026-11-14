//! Source-bound notification projection, independent of shared-artifact storage.
use crate::dependency_index::PageManifest;
use crate::replay::redis::pubsub::{NotificationIdentity, NotificationLaneEvidence};
use crate::replay::report::global_evidence::artifact::{ArtifactReference, digest};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
const VERSION: u32 = 1;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SharedReference(ArtifactReference);
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceIdentity {
    sha256: String,
    bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SharedLane {
    pub identity: NotificationIdentity,
    pub pages: PageManifest,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SharedInventory {
    version: u32,
    source: SourceIdentity,
    pub lanes: Vec<SharedLane>,
}
fn key(source: &SourceIdentity, lanes: &[SharedLane]) -> Result<String> {
    let layout: Vec<_> = lanes
        .iter()
        .map(|lane| (&lane.identity, lane.pages.count))
        .collect();
    // Legacy recordings may locate native subscription proof in a Case file;
    // include its exact confirmation in addition to the Global file digest.
    digest(&("global-pubsub-notifications", VERSION, source, layout))
}
impl SharedReference {
    pub(crate) fn key(&self) -> &str {
        self.0.key()
    }
    pub(crate) fn validate_pages(&self, report: &Path) -> Result<()> {
        let (inventory, root) = self.load(report)?;
        for lane in inventory.lanes {
            let pages = crate::dependency_index::Paged::<
                crate::dependency_index::global::NotificationEntry,
            >::restore(lane.pages.resolve(&root)?)?;
            for page in 0..pages.pages() {
                pages.read_page(page)?;
            }
        }
        Ok(())
    }
    pub(crate) fn load(&self, report: &Path) -> Result<(SharedInventory, PathBuf)> {
        let (inventory, directory) = self.0.load::<SharedInventory>(report)?;
        inventory.validate()?;
        ensure!(
            key(&inventory.source, &inventory.lanes)? == self.0.key(),
            "shared notification projection binding changed"
        );
        Ok((inventory, directory))
    }
    pub(crate) fn stage(&self, source: &Path, destination: &Path) -> Result<Self> {
        self.load(source)?;
        Ok(Self(self.0.stage::<SharedInventory>(
            source,
            destination,
            |inventory, root, staging| {
                let mut retained = inventory.clone();
                for (index, lane) in retained.lanes.iter_mut().enumerate() {
                    lane.pages = lane
                        .pages
                        .clone()
                        .resolve(root)?
                        .retain_into(&staging.join(format!("lane-{index}")))?
                        .relative_to(staging)?;
                }
                Ok(retained)
            },
        )?))
    }
}
impl SharedInventory {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION && self.source.sha256.len() == 64,
            "unsupported shared notification inventory"
        );
        let mut anchors = std::collections::BTreeSet::new();
        for lane in &self.lanes {
            ensure!(
                lane.pages.count > 0 && lane.identity.subscription_sequence > 0,
                "invalid shared notification lane"
            );
            ensure!(
                anchors.insert((
                    lane.identity.connection_id,
                    lane.identity.subscription_sequence
                )),
                "duplicate shared notification anchor"
            );
            lane.identity.validate()?;
        }
        Ok(())
    }
}
pub(crate) fn retain(report: &Path, lanes: &[NotificationLaneEvidence]) -> Result<SharedReference> {
    retain_at(report, lanes, false)
}
pub(crate) fn retain_portable(
    report: &Path,
    lanes: &[NotificationLaneEvidence],
) -> Result<SharedReference> {
    retain_at(report, lanes, true)
}
fn retain_at(
    report: &Path,
    lanes: &[NotificationLaneEvidence],
    portable: bool,
) -> Result<SharedReference> {
    let first = lanes
        .first()
        .context("empty shared notification inventory")?;
    first.source.validate()?;
    ensure!(
        lanes
            .iter()
            .all(|lane| lane.source.path() == first.source.path()),
        "notification inventory spans different Global sources"
    );
    let (index, _) = crate::dependency_index::global::load_global_index(
        first.source.path(),
        crate::protocols::replay::source::validate_index_record,
    )?;
    first.source.validate()?;
    let source = SourceIdentity {
        sha256: index.sha256,
        bytes: index.stamp.size,
    };
    let projected: Vec<_> = lanes
        .iter()
        .map(|lane| SharedLane {
            identity: lane.identity.clone(),
            pages: lane.pages.manifest(),
        })
        .collect();
    let key = key(&source, &projected)?;
    let imported = if portable {
        None
    } else if let Some(reference) = ArtifactReference::existing::<SharedInventory>(report, &key)? {
        Some(SharedReference(reference))
    } else {
        import_notifications(first.source.path(), report, &key)?
    };
    let reference = if let Some(reference) = imported {
        reference
    } else {
        let build = |staging: &Path| {
            let mut retained = Vec::new();
            for (index, lane) in projected.into_iter().enumerate() {
                retained.push(SharedLane {
                    identity: lane.identity,
                    pages: lane
                        .pages
                        .retain_into(&staging.join(format!("lane-{index}")))?
                        .relative_to(staging)?,
                });
            }
            Ok(SharedInventory {
                version: VERSION,
                source,
                lanes: retained,
            })
        };
        SharedReference(if portable {
            ArtifactReference::retain_portable(report, key, build)?
        } else {
            ArtifactReference::retain(report, key, build)?
        })
    };
    let (inventory, _) = reference.load(report)?;
    ensure!(
        inventory.lanes.len() == lanes.len()
            && inventory.lanes.iter().zip(lanes).all(|(sealed, live)| {
                sealed.pages.count == live.pages.count && sealed.identity == live.identity
            }),
        "shared notification inventory differs from admitted Replay lanes"
    );
    Ok(reference)
}

fn import_notifications(
    source: &Path,
    report: &Path,
    key: &str,
) -> Result<Option<SharedReference>> {
    let Some((marker, value)) =
        crate::replay::report::global_evidence::preparation::read_extension(
            source,
            "notifications",
        )?
    else {
        return Ok(None);
    };
    let reference: SharedReference = match serde_json::from_value(value) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if reference.key() != key {
        return Ok(None);
    }
    match reference
        .validate_pages(&marker)
        .and_then(|()| reference.stage(&marker, report))
    {
        Ok(reference) => Ok(Some(reference)),
        Err(error) => {
            tracing::warn!(error=%error, "optional recording notification projection is unavailable; rebuilding from Source");
            Ok(None)
        }
    }
}
