use super::*;
use crate::dependency_index::global::{GLOBAL_FRAGMENT, GlobalBuilder, GlobalIndex};
use crate::dependency_index::{Builder, FRAGMENT, FileStamp};

pub(super) async fn write_dependency_summary(
    dir: &Path,
    dependencies_filename: &str,
    summary_filename: &str,
) -> Result<()> {
    let path = dir.join(dependencies_filename);
    let input = match crate::dependency_index::RecordStream::open(&path) {
        Ok(input) => input,
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
        let mut input = input;
        let stamp = input.stamp.clone();
        let mut case_index = case_dependencies.then(|| Builder::new(stamp.clone()));
        let scoped = crate::dependency_index::scoped::view_path(&path).is_some();
        if scoped && let Some(index) = &mut case_index {
            index.set_scoped();
        }
        let mut global_index = if case_dependencies {
            None
        } else {
            Some(GlobalBuilder::new(&dir, stamp.clone())?)
        };
        let mut summary = DependencySummaryBuilder::default();
        if scoped && let Some(index) = &mut global_index {
            index.set_scoped();
        }
        while let Some((location, raw)) = input.next()? {
            let value = if raw.iter().all(u8::is_ascii_whitespace) {
                None
            } else {
                Some(serde_json::from_slice::<Value>(raw)?)
            };
            if let Some(value) = &value {
                summary.observe(value);
            }
            if let Some(index) = &mut case_index {
                index.observe_at(&location, raw, value.as_ref())?;
            }
            if let Some(index) = &mut global_index {
                index.observe(location, raw, value)?;
            }
        }
        crate::dependency_index::scoped::validate_stamp(&path, &stamp)?;
        if let Some(index) = case_index {
            crate::dependency_index::store::write_json(&dir.join(FRAGMENT), &index.finish()?)?;
        }
        if let Some(index) = global_index {
            crate::dependency_index::store::write_json(
                &dir.join(GLOBAL_FRAGMENT),
                &index.finish()?,
            )?;
        }
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
            let fragment = dir.join(GLOBAL_FRAGMENT);
            if fragment.is_file() {
                let mut index: GlobalIndex = crate::dependency_index::store::read_json(&fragment)?;
                let stamp = FileStamp::read(&dir.join("global-dependencies.jsonl"))?;
                let mut previous = index.stamp.clone();
                previous.changed = stamp.changed;
                anyhow::ensure!(
                    previous == stamp,
                    "Global dependency bytes changed during artifact ownership assignment"
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
