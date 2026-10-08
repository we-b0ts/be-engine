use super::*;
use crate::dependency_index::{Builder, FRAGMENT, FileStamp};

pub(super) async fn write_dependency_summary(
    dir: &Path,
    dependencies_filename: &str,
    summary_filename: &str,
) -> Result<()> {
    let path = dir.join(dependencies_filename);
    let raw = match super::super::storage::read_to_string(&path).await {
        Ok(raw) => raw,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error).context("failed to read dependencies for summary"),
    };
    let dir_owned = dir.to_path_buf();
    let case_dependencies = dependencies_filename == "dependencies.jsonl";
    let payload = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let dir = dir_owned;
        // Summary and index share the bytes already read before case publication.
        // Blank lines and the final line terminator participate in byte offsets.
        let stamp = FileStamp::read(&path)?;
        let mut index = Builder::new(stamp.clone());
        let mut summary = DependencySummaryBuilder::default();
        for (line, raw) in raw.split_inclusive('\n').enumerate() {
            let value = if raw.trim().is_empty() {
                None
            } else {
                Some(serde_json::from_str::<Value>(raw)?)
            };
            index.observe(line + 1, raw.as_bytes(), value.as_ref())?;
            if let Some(value) = &value {
                summary.observe(value);
            }
        }
        anyhow::ensure!(
            FileStamp::read(&path)? == stamp,
            "dependency file changed before publication"
        );
        let index = index.finish()?;
        let fragment = if case_dependencies {
            dir.join(FRAGMENT)
        } else {
            dir.join(".global-dependency-index.json")
        };
        crate::dependency_index::store::write_json(&fragment, &index)?;
        let summary = summary.finish();
        let mut payload = serde_json::to_vec_pretty(&summary)?;
        payload.push(b'\n');
        Ok(payload)
    })
    .await
    .context("dependency summary/index writer failed")??;
    super::super::storage::write(&dir.join(summary_filename), &payload).await
}

/// Recorder owns the completed bytes across this metadata-only ownership change.
/// Refresh ctime only when size, inode and modification time are still identical.
pub(crate) async fn refresh_owned_dependency_indexes(
    root: &Path,
    owner: crate::artifact_owner::ArtifactOwner,
) -> Result<()> {
    let root = root.to_path_buf();
    let fragments = tokio::task::spawn_blocking(move || -> Result<Vec<std::path::PathBuf>> {
        let mut pending = vec![root];
        let mut refreshed = Vec::new();
        while let Some(dir) = pending.pop() {
            for (dependency, fragment) in [
                ("dependencies.jsonl", FRAGMENT),
                ("global-dependencies.jsonl", ".global-dependency-index.json"),
            ] {
                let fragment = dir.join(fragment);
                if !fragment.is_file() {
                    continue;
                }
                let mut index: crate::dependency_index::FileIndex =
                    crate::dependency_index::store::read_json(&fragment)?;
                let stamp = FileStamp::read(&dir.join(dependency))?;
                let mut previous = index.stamp.clone();
                previous.changed = stamp.changed;
                anyhow::ensure!(
                    previous == stamp,
                    "dependency bytes changed during artifact ownership assignment"
                );
                index.stamp = stamp;
                crate::dependency_index::store::write_json(&fragment, &index)?;
                refreshed.push(fragment);
            }
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    pending.push(entry.path());
                }
            }
        }
        Ok(refreshed)
    })
    .await
    .context("dependency fragment ownership refresh failed")??;
    for fragment in fragments {
        owner.assign_to(&fragment).await?;
    }
    Ok(())
}
