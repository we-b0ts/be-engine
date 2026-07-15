use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::discovery::{PublishedCase, inventory_id, select_group_cases};
use super::{CaseGroupStatus, PatternOutcome};

const INDEX_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CaseGroupIndex {
    version: u32,
    case_source: PathBuf,
    pub(super) source_revision: String,
    pub(super) groups: Vec<CaseGroupRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CaseGroupRecord {
    pub(super) status: CaseGroupStatus,
    pub(super) group_id: String,
    pub(super) method: String,
    pub(super) source_route: String,
    pub(super) pattern: Option<String>,
    pub(super) pattern_outcome: PatternOutcome,
    pub(super) group_dir: Option<PathBuf>,
    pub(super) case_ids: Vec<String>,
    pub(super) member_dirs: Vec<PathBuf>,
    pub(super) case_inventory_id: String,
    pub(super) manifest: PathBuf,
    pub(super) report_path: PathBuf,
}

pub(super) fn load_or_create_index(
    output: &Path,
    case_source: &Path,
    source_revision: &str,
) -> Result<CaseGroupIndex> {
    let metadata = match fs::symlink_metadata(output) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CaseGroupIndex {
                version: INDEX_VERSION,
                case_source: case_source.to_path_buf(),
                source_revision: source_revision.to_string(),
                groups: Vec::new(),
            });
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect group index {}", output.display()));
        }
    };
    ensure!(metadata.is_file(), "group index must be a regular file");
    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to read a symlinked group index"
    );
    let index: CaseGroupIndex = serde_json::from_slice(
        &fs::read(output)
            .with_context(|| format!("failed to read group index {}", output.display()))?,
    )
    .with_context(|| format!("failed to parse group index {}", output.display()))?;
    ensure!(
        index.version == INDEX_VERSION,
        "unsupported group index version {}",
        index.version
    );
    ensure!(
        index.case_source == case_source,
        "group index belongs to a different case source"
    );
    ensure!(
        index.source_revision == source_revision,
        "source revision changed from {} to {}; start a reviewed new group index",
        index.source_revision,
        source_revision
    );
    for group in &index.groups {
        ensure!(
            group.manifest == output && group.report_path == output,
            "group {} references a different manifest or report path",
            group.group_id
        );
    }
    Ok(index)
}

pub(super) fn validate_index(index: &CaseGroupIndex, cases: &[PublishedCase]) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut members = BTreeSet::new();
    let mut group_ids = BTreeSet::new();
    for group in &index.groups {
        let expected_status = if group.pattern.is_some() {
            CaseGroupStatus::Created
        } else {
            CaseGroupStatus::AlreadyCanonical
        };
        ensure!(
            group.status == expected_status,
            "group {} has an invalid persisted status",
            group.group_id
        );
        ensure!(
            group_ids.insert(&group.group_id),
            "duplicate group id {}",
            group.group_id
        );
        let current_dir = group
            .group_dir
            .as_deref()
            .or_else(|| group.member_dirs.first().map(PathBuf::as_path))
            .context("group has no member directories")?;
        let selected = select_group_cases(
            cases,
            current_dir,
            &group.method,
            &group.source_route,
            group.pattern.as_deref(),
        )?;
        let selected_ids = selected
            .iter()
            .map(|case| case.id.clone())
            .collect::<Vec<_>>();
        let selected_members = selected
            .iter()
            .map(|case| case.member_dir.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        ensure!(
            selected_ids == group.case_ids
                && selected_members == group.member_dirs
                && inventory_id(&selected) == group.case_inventory_id,
            "case inventory for group {} is stale",
            group.group_id
        );
        for id in &group.case_ids {
            ensure!(ids.insert(id), "case id {id} belongs to overlapping groups");
        }
        for member in &group.member_dirs {
            ensure!(
                members.insert(member),
                "case directory {} belongs to overlapping groups",
                member.display()
            );
        }
    }
    for (position, left) in index.groups.iter().enumerate() {
        for right in index.groups.iter().skip(position + 1) {
            ensure!(
                !route_specs_overlap(
                    left,
                    &right.method,
                    &right.source_route,
                    right.pattern.as_deref()
                ),
                "groups {} and {} have overlapping route specifications",
                left.group_id,
                right.group_id
            );
        }
    }
    Ok(())
}

pub(super) fn reject_membership_overlap(
    groups: &[CaseGroupRecord],
    case_ids: &[String],
    member_dirs: &[PathBuf],
) -> Result<()> {
    for group in groups {
        ensure!(
            !case_ids.iter().any(|id| group.case_ids.contains(id)),
            "new group overlaps case ids owned by {}",
            group.group_id
        );
        ensure!(
            !member_dirs
                .iter()
                .any(|member| group.member_dirs.contains(member)),
            "new group overlaps member directories owned by {}",
            group.group_id
        );
    }
    Ok(())
}

pub(super) fn reject_route_overlap(
    groups: &[CaseGroupRecord],
    method: &str,
    source_route: &str,
    pattern: Option<&str>,
) -> Result<()> {
    for group in groups {
        ensure!(
            !route_specs_overlap(group, method, source_route, pattern),
            "new route specification overlaps existing group {}",
            group.group_id
        );
    }
    Ok(())
}

fn route_specs_overlap(
    existing: &CaseGroupRecord,
    method: &str,
    source_route: &str,
    pattern: Option<&str>,
) -> bool {
    if existing.method != method {
        return false;
    }
    route_keys_overlap(
        existing
            .pattern
            .as_deref()
            .unwrap_or(&existing.source_route),
        pattern.unwrap_or(source_route),
    )
}

fn route_keys_overlap(left: &str, right: &str) -> bool {
    let left = left.split('/').collect::<Vec<_>>();
    let right = right.split('/').collect::<Vec<_>>();
    left.len() == right.len()
        && left
            .iter()
            .copied()
            .zip(right)
            .all(|(left, right)| left == right || left == "*" || right == "*")
}

pub(super) fn prepare_output_path(output: &Path, case_source: &Path) -> Result<PathBuf> {
    let output = absolute_clean(output)?;
    ensure!(
        !output.starts_with(case_source),
        "group index must live outside the canonical case source"
    );
    let file_name = output
        .file_name()
        .context("group index output must name a file")?;
    let parent = output
        .parent()
        .context("group index output has no parent")?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create group index directory {}",
            parent.display()
        )
    })?;
    let parent = fs::canonicalize(parent).with_context(|| {
        format!(
            "failed to resolve group index directory {}",
            parent.display()
        )
    })?;
    ensure!(
        !parent.starts_with(case_source),
        "group index must live outside the canonical case source"
    );
    Ok(parent.join(file_name))
}

fn absolute_clean(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut clean = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                clean.pop();
            }
            other => clean.push(other.as_os_str()),
        }
    }
    Ok(clean)
}

pub(super) fn write_index(path: &Path, index: &CaseGroupIndex) -> Result<()> {
    let mut payload = serde_json::to_vec_pretty(index)?;
    payload.push(b'\n');
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid group index filename")?;
    let mut temporary = None;
    for attempt in 0..100 {
        let candidate = path.with_file_name(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("failed to create temporary group index"),
        }
    }
    let (temporary, mut file) = temporary.context("failed to reserve temporary group index")?;
    let result = (|| -> Result<()> {
        file.write_all(&payload)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
            .with_context(|| format!("failed to publish group index {}", path.display()))?;
        File::open(path.parent().context("group index has no parent")?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
