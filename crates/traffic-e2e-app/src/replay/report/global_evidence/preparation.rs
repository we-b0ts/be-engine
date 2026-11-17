//! Optional, portable recording-time projections. These are derived Source
//! indexes, never independent Target witnesses or a substitute for Replay admission.
use super::artifact::ArtifactReference;
use super::regular_store::{Identity, Inventory};
use crate::dependency_index::store;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use traffic_protocol::connection::NativeFuture;
use traffic_replay::report::{GlobalReportProjection, ReportRows};

const MARKER: &str = ".global-report-preparation.json";
const VERSION: u32 = 3;
#[cfg(test)]
mod tests;

pub(crate) trait PreparedSource: GlobalReportProjection + Send {
    fn retain_extensions(&self, marker: &Path) -> Result<BTreeMap<String, serde_json::Value>>;
}

pub(crate) trait SourcePreparation: Send + Sync {
    fn policy(&self) -> &str;
    fn validate_record(&self, value: &serde_json::Value) -> Result<()>;
    fn load<'a>(&'a self, source: &'a Path) -> NativeFuture<'a, Box<dyn PreparedSource>>;
}

pub(crate) fn read_extension(
    source: &Path,
    name: &str,
) -> Result<Option<(std::path::PathBuf, serde_json::Value)>> {
    let marker = marker_path(source)?;
    let status: Preparation = match store::read_json(&marker) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if status.version != VERSION || status.status != "ready" {
        return Ok(None);
    }
    Ok(status
        .extensions
        .get(name)
        .map(|value| (marker, value.clone())))
}

fn marker_path(source: &Path) -> Result<std::path::PathBuf> {
    Ok(crate::dependency_index::recording::root(source)
        .unwrap_or(
            source
                .parent()
                .context("Global Source has no parent")?
                .to_owned(),
        )
        .join(MARKER))
}

#[derive(Debug, Serialize, Deserialize)]
struct Preparation {
    version: u32,
    status: String,
    policy: String,
    source_sha256: Option<String>,
    inventories: BTreeMap<String, ArtifactReference>,
    #[serde(flatten)]
    extensions: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

pub(crate) fn policy_identity<T: Serialize + ?Sized>(
    rules: &T,
    fingerprint: Option<&str>,
) -> Result<String> {
    Ok(crate::policy_evidence::digest(&serde_json::to_vec(&(
        rules,
        fingerprint,
    ))?))
}

pub(crate) async fn prewarm(run: &Path, preparation: Arc<dyn SourcePreparation>) -> Result<()> {
    let policy = preparation.policy().to_owned();
    let source = run.join("global-dependencies.jsonl");
    let mut status = Preparation {
        version: VERSION,
        status: "prewarm_failed".into(),
        policy: policy.clone(),
        source_sha256: None,
        inventories: BTreeMap::new(),
        extensions: BTreeMap::new(),
        reason: None,
    };
    if !crate::dependency_index::scoped::exists(&source) {
        status.status = "not_needed".into();
        status.reason = Some("recording has no Global dependency file".into());
        return store::write_json(&run.join(MARKER), &status);
    }
    let result = async {
        let stamp = crate::dependency_index::FileStamp::read(&source)?;
        let prepared = preparation.load(&source).await?;
        let run = run.to_owned();
        tokio::task::spawn_blocking(move || -> Result<_> {
            let (index, _) =
                crate::dependency_index::global::load_global_index(&source, |value| {
                    preparation.validate_record(value)
                })?;
            ensure!(
                index.stamp == stamp,
                "Global Source changed during recording preparation"
            );
            let source_sha256 = if crate::dependency_index::recording::root(&source).is_some() {
                let (_, manifest) = crate::dependency_index::recording::manifest(&source)?;
                // Use the same sealed-run identity as Replay, without consulting
                // a Target workflow or importing a later attribution overlay.
                let (_, empty_snapshot) =
                    crate::rewrite::freeze_dependency_attribution(None, &run, &manifest.run_id)?;
                let empty_snapshot = Some(empty_snapshot);
                crate::policy_evidence::digest(&serde_json::to_vec(&(
                    manifest.files,
                    empty_snapshot,
                ))?)
            } else {
                index.sha256.clone()
            };
            let marker = run.join(MARKER);
            let view = prepared.as_ref();
            let mut inventories = BTreeMap::new();
            for protocol in view.global_report_protocols() {
                let protocol = protocol.as_str();
                let identity = Identity {
                    source_sha256: source_sha256.clone(),
                    source_bytes: index.stamp.size,
                    policy: policy.clone(),
                    protocol: protocol.into(),
                    layout: view.global_report_layout(protocol)?,
                    semantics: view.global_report_semantics(protocol),
                };
                let reference = super::regular::retain_reference(
                    &marker,
                    identity.clone(),
                    true,
                    None,
                    |visitor| view.visit_global_report(protocol, ReportRows::Core, visitor),
                )?;
                let (inventory, _) = reference.load::<Inventory>(&marker)?;
                inventory.validate(&reference)?;
                ensure!(
                    inventory.identity == identity,
                    "recording Global projection identity changed"
                );
                inventories.insert(protocol.to_owned(), reference);
            }
            let extensions = prepared.retain_extensions(&marker)?;
            ensure!(
                crate::dependency_index::FileStamp::read(&source)? == stamp,
                "Global Source changed while preparing report projection"
            );
            Ok((source_sha256, inventories, extensions))
        })
        .await
        .context("recording Global projection task failed")?
    }
    .await;
    match result {
        Ok((sha256, inventories, extensions)) => {
            status.status = "ready".into();
            status.source_sha256 = Some(sha256);
            status.inventories = inventories;
            status.extensions = extensions;
        }
        Err(error) => {
            status.reason = Some(format!("{error:#}"));
            tracing::warn!(run_dir=%run.display(), error=%error, "optional Global report prewarm failed; original recording is preserved");
        }
    }
    // Caller treats even a derived-state publication failure as an optimization
    // failure; it cannot turn a Source recording into a failed recording.
    store::write_json(&run.join(MARKER), &status)
}

pub(super) fn import(
    source: &Path,
    report: &Path,
    expected: &Identity,
) -> Result<Option<ArtifactReference>> {
    // The Source owner is passed explicitly by the initialize call; arbitrary
    // ancestor searches and external cache paths are intentionally unsupported.
    let marker = marker_path(source)?;
    {
        let marker = marker.as_path();
        let status: Preparation = match store::read_json(marker) {
            Ok(value) => value,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => {
                tracing::warn!(error=%error, "recording Global prewarm metadata is unavailable; rebuilding");
                return Ok(None);
            }
        };
        if status.version != VERSION
            || status.status != "ready"
            || status.policy != expected.policy
            || status.source_sha256.as_deref() != Some(&expected.source_sha256)
        {
            return Ok(None);
        }
        let Some(reference) = status.inventories.get(&expected.protocol) else {
            return Ok(None);
        };
        if reference.key() != expected.key()? {
            return Ok(None);
        }
        let imported = (|| -> Result<ArtifactReference> {
            let (inventory, root) = reference.load::<Inventory>(marker)?;
            inventory.validate(reference)?;
            ensure!(
                &inventory.identity == expected,
                "recording Global projection does not match current Source/policy/layout"
            );
            // Only the first cross-owner import traverses pages. Once retained,
            // local manifests win and all report reads remain lazy and strict.
            for page in 0..inventory.pages.len() {
                inventory.read_page(&root, page)?;
            }
            reference.stage::<Inventory>(marker, report, |inventory, root, staging| {
                inventory.stage(root, staging)
            })
        })();
        match imported {
            Ok(reference) => Ok(Some(reference)),
            Err(error) => {
                tracing::warn!(error=%error, "optional recording Global projection is unavailable; rebuilding from Source");
                Ok(None)
            }
        }
    }
}
