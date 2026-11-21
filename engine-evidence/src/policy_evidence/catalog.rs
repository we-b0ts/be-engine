//! A sealed private observation directory, separate from the bounded public
//! manifest. Its content digest is authenticated by the session signing key.
use super::limits::MAX_CATALOG_BYTES;
use super::*;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    sync::Arc,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphArtifact {
    pub artifact: String,
    pub sha256: String,
}

impl WitnessManifest {
    pub fn graph(&self) -> Option<&ObservationGraph> {
        self.observations
            .as_ref()
            .or_else(|| self.graph_cache.get().map(|(_, graph)| graph.as_ref()))
    }
    pub(super) fn externalize(&mut self, base: &Path, key: &[u8]) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let graph = self
            .observations
            .take()
            .context("missing observation directory")?;
        let mut sources = std::collections::BTreeMap::new();
        for blob in &graph.blobs {
            if let Some(source) = &blob.source {
                let record = &source.record;
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    sources.entry((&record.path, record.view.as_ref().map(|(path, _)| path)))
                {
                    record.validate()?;
                    entry.insert(());
                }
            }
        }
        let bytes = serde_json::to_vec(&graph)?;
        ensure!(
            bytes.len() as u64 <= MAX_CATALOG_BYTES,
            "policy observation directory exceeds its metadata budget"
        );
        let artifact = format!(
            "{}-graph.jsonl",
            base.file_stem().unwrap().to_string_lossy()
        );
        let path = base.with_file_name(&artifact);
        let sha256 = digest(&bytes);
        if path.exists() {
            ensure!(
                read_catalog(&path)?.0 == sha256,
                "policy observation directory changed before sealing"
            );
        } else {
            let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(temp, &path)?;
        }
        self.version = 4;
        self.graph_artifact = Some(GraphArtifact {
            artifact,
            sha256: sha256.clone(),
        });
        self.graph_cache
            .set((sha256, Arc::new(graph)))
            .map_err(|_| anyhow::anyhow!("observation directory was already published"))?;
        if !self.graph().unwrap().key_envelope.is_empty() {
            self.authentication = super::v2::manifest_signature(self, key)?;
        }
        Ok(())
    }
    pub fn load_graph(&self, report: &Path) -> Result<()> {
        if self.version != 4 {
            return Ok(());
        }
        ensure!(
            self.observations.is_none(),
            "external observation directory cannot be overridden inline"
        );
        let reference = self
            .graph_artifact
            .as_ref()
            .context("missing policy observation directory reference")?;
        let (sha256, graph) =
            read_catalog(&super::storage::named_path(report, &reference.artifact)?)?;
        ensure!(
            sha256 == reference.sha256 && graph.authentication.is_empty(),
            "policy observation directory changed after publication"
        );
        if let Some((cached, _)) = self.graph_cache.get() {
            ensure!(
                cached == &sha256,
                "policy observation directory cache belongs to another artifact"
            );
        } else {
            let _ = self.graph_cache.set((sha256, Arc::new(graph)));
        }
        Ok(())
    }
}

fn read_catalog(path: &Path) -> Result<(String, ObservationGraph)> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= MAX_CATALOG_BYTES,
        "policy observation directory must be a bounded regular file"
    );
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_CATALOG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "policy observation directory size changed"
    );
    Ok((digest(&bytes), serde_json::from_slice(&bytes)?))
}

pub(super) fn stage(source: &Path, destination: &Path, manifest: &WitnessManifest) -> Result<()> {
    manifest.load_graph(source)?;
    let reference = manifest.graph_artifact.as_ref().unwrap();
    let src = super::storage::named_path(source, &reference.artifact)?;
    let dst = super::storage::named_path(destination, &reference.artifact)?;
    super::storage::stage(source, destination, manifest.graph().unwrap())?;
    if src != dst {
        if dst.exists() {
            ensure!(
                read_catalog(&dst)?.0 == reference.sha256,
                "policy observation directory publication collision"
            );
        } else {
            std::fs::copy(src, &dst)?;
        }
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
