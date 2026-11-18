use super::*;
use crate::dependency_index::global::{GLOBAL_FRAGMENT, GlobalBuilder};
use crate::dependency_index::{Builder, FRAGMENT};

mod ownership;
pub use ownership::refresh_owned_dependency_indexes;

pub(super) async fn write_dependency_summary(
    dir: &Path,
    dependencies_filename: &str,
    summary_filename: &str,
    evidence: Arc<EvidenceRegistry>,
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
        let mut case_index =
            case_dependencies.then(|| Builder::with_evidence(stamp.clone(), (*evidence).clone()));
        let scope_membership_sha256 = if case_dependencies {
            input.scope_membership_sha256()?
        } else {
            None
        };
        let scoped = crate::dependency_index::scoped::view_path(&path).is_some();
        if scoped && let Some(index) = &mut case_index {
            index.set_scoped();
        }
        // Scoped recordings publish their authenticated per-scope Global
        // indexes at seal. The root-level fragment only serves flat inputs.
        let mut global_index = if case_dependencies || scoped {
            None
        } else {
            Some(GlobalBuilder::with_evidence(
                &dir,
                stamp.clone(),
                (*evidence).clone(),
            )?)
        };
        let mut summary = DependencySummaryBuilder::new((*evidence).clone());
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
            let mut index = index.finish()?;
            index.scope_membership_sha256 = scope_membership_sha256;
            crate::dependency_index::store::write_json(&dir.join(FRAGMENT), &index)?;
        }
        if let Some(index) = global_index {
            crate::dependency_index::store::write_json(
                &dir.join(GLOBAL_FRAGMENT),
                &index.finish()?,
            )?;
        }
        let summary = summary.finish()?;
        let mut payload = serde_json::to_vec_pretty(&summary)?;
        payload.push(b'\n');
        Ok(payload)
    })
    .await
    .context("dependency summary/index writer failed")??;
    super::super::storage::write(&dir.join(summary_filename), &payload).await
}
