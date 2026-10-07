use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::path_pattern::path_patterns_overlap;

use super::discovery::{PublishedCase, inventory_id, portable_inventory_id, select_group_cases};
use super::{CaseGroupStatus, PatternOutcome};

const LEGACY_INDEX_VERSION: u32 = 1;
const INDEX_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum CaseGroupPathAnchor {
    #[default]
    Absolute,
    TargetRoot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CaseGroupIndex {
    pub(super) version: u32,
    #[serde(default)]
    pub(super) path_anchor: CaseGroupPathAnchor,
    pub(super) case_source: PathBuf,
    pub(super) source_revision: String,
    pub(super) groups: Vec<CaseGroupRecord>,
}

#[derive(Debug, Clone)]
pub(super) struct IndexPathStorage {
    anchor: CaseGroupPathAnchor,
    target_root: Option<PathBuf>,
}

impl IndexPathStorage {
    fn for_new_index(
        case_source: &Path,
        output: &Path,
        target_root: Option<&Path>,
    ) -> Result<Self> {
        let Some(target_root) = target_root else {
            return Ok(Self::absolute());
        };
        let target_root = fs::canonicalize(target_root)
            .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
        if case_source.starts_with(&target_root) && output.starts_with(&target_root) {
            Ok(Self {
                anchor: CaseGroupPathAnchor::TargetRoot,
                target_root: Some(target_root),
            })
        } else {
            Ok(Self::absolute())
        }
    }

    pub(super) fn for_index(index: &CaseGroupIndex, case_source: &Path) -> Result<Self> {
        match index.path_anchor {
            CaseGroupPathAnchor::Absolute => Ok(Self::absolute()),
            CaseGroupPathAnchor::TargetRoot => {
                validate_relative_path(&index.case_source)?;
                ensure!(
                    case_source.ends_with(&index.case_source),
                    "group index target-root-relative case source does not match the requested case source"
                );
                let mut target_root = case_source.to_path_buf();
                for _ in index.case_source.components() {
                    ensure!(
                        target_root.pop(),
                        "group index target-root-relative case source has no target root"
                    );
                }
                ensure!(
                    !target_root.as_os_str().is_empty(),
                    "group index target-root-relative case source has an empty target root"
                );
                Ok(Self {
                    anchor: CaseGroupPathAnchor::TargetRoot,
                    target_root: Some(target_root),
                })
            }
        }
    }

    fn absolute() -> Self {
        Self {
            anchor: CaseGroupPathAnchor::Absolute,
            target_root: None,
        }
    }

    pub(super) fn anchor(&self) -> CaseGroupPathAnchor {
        self.anchor
    }

    pub(super) fn persist(&self, path: &Path) -> Result<PathBuf> {
        match &self.target_root {
            Some(target_root) => path
                .strip_prefix(target_root)
                .map(Path::to_path_buf)
                .with_context(|| {
                    format!(
                        "path {} is outside target root {}",
                        path.display(),
                        target_root.display()
                    )
                }),
            None => Ok(path.to_path_buf()),
        }
    }

    pub(super) fn resolve(&self, path: &Path) -> Result<PathBuf> {
        match &self.target_root {
            Some(target_root) => {
                validate_relative_path(path)?;
                let resolved = fs::canonicalize(target_root.join(path)).with_context(|| {
                    format!(
                        "failed to resolve target-root-relative group index path {}",
                        path.display()
                    )
                })?;
                ensure!(
                    resolved.starts_with(target_root),
                    "target-root-relative group index path escapes the target root"
                );
                Ok(resolved)
            }
            None => fs::canonicalize(path)
                .with_context(|| format!("failed to resolve group index path {}", path.display())),
        }
    }
}

fn validate_relative_path(path: &Path) -> Result<()> {
    ensure!(
        !path.as_os_str().is_empty() && !path.is_absolute(),
        "target-root-relative group index path must be a non-empty relative path"
    );
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "target-root-relative group index path must not contain '.' or '..'"
    );
    Ok(())
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
    target_root: Option<&Path>,
) -> Result<CaseGroupIndex> {
    let metadata = match fs::symlink_metadata(output) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let storage = IndexPathStorage::for_new_index(case_source, output, target_root)?;
            return Ok(CaseGroupIndex {
                version: INDEX_VERSION,
                path_anchor: storage.anchor(),
                case_source: storage.persist(case_source)?,
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
    let index = read_index(output)?;
    ensure!(
        matches!(index.version, LEGACY_INDEX_VERSION | INDEX_VERSION),
        "unsupported group index version {}",
        index.version
    );
    let storage = IndexPathStorage::for_index(&index, case_source)?;
    ensure!(
        storage.resolve(&index.case_source)? == case_source,
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
            storage.resolve(&group.manifest)? == output
                && storage.resolve(&group.report_path)? == output,
            "group {} references a different manifest or report path",
            group.group_id
        );
    }
    Ok(index)
}

pub(super) fn read_index(output: &Path) -> Result<CaseGroupIndex> {
    let metadata = fs::symlink_metadata(output)
        .with_context(|| format!("failed to inspect group index {}", output.display()))?;
    ensure!(metadata.is_file(), "group index must be a regular file");
    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to read a symlinked group index"
    );
    serde_json::from_slice(
        &fs::read(output)
            .with_context(|| format!("failed to read group index {}", output.display()))?,
    )
    .with_context(|| format!("failed to parse group index {}", output.display()))
}

pub(super) fn legacy_index_locations(index: &CaseGroupIndex) -> Result<(PathBuf, PathBuf)> {
    ensure!(
        index.version == LEGACY_INDEX_VERSION && index.path_anchor == CaseGroupPathAnchor::Absolute,
        "group index is not a legacy absolute-path index"
    );
    ensure!(
        index.case_source.is_absolute(),
        "legacy group index case source must be absolute"
    );
    let output = index
        .groups
        .first()
        .map(|group| group.manifest.clone())
        .context("legacy group index contains no case groups")?;
    ensure!(
        output.is_absolute(),
        "legacy group index output must be absolute"
    );
    ensure!(
        index
            .groups
            .iter()
            .all(|group| group.manifest == output && group.report_path == output),
        "legacy group index contains inconsistent manifest or report paths"
    );
    Ok((index.case_source.clone(), output))
}

pub(super) fn validate_index(
    index: &CaseGroupIndex,
    storage: &IndexPathStorage,
    case_source: &Path,
    cases: &[PublishedCase],
) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut group_ids = BTreeSet::new();
    for group in &index.groups {
        let expected_status = if group.group_dir.is_none() {
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
        let stored_current_dir = group
            .group_dir
            .as_deref()
            .or_else(|| group.member_dirs.first().map(PathBuf::as_path))
            .context("group has no member directories")?;
        let current_dir = storage.resolve(stored_current_dir)?;
        let selected = select_group_cases(
            cases,
            &current_dir,
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
        let persisted_members = group
            .member_dirs
            .iter()
            .map(|member| storage.resolve(member))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            selected_ids == group.case_ids
                && selected_members == persisted_members
                && case_inventory_id(index, case_source, &selected)? == group.case_inventory_id,
            "case inventory for group {} is stale",
            group.group_id
        );
        for id in &group.case_ids {
            ensure!(ids.insert(id), "case id {id} belongs to overlapping groups");
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

pub(super) fn validate_loaded_index(
    index: &CaseGroupIndex,
    storage: &IndexPathStorage,
    output: &Path,
    case_source: &Path,
    cases: &[PublishedCase],
) -> Result<()> {
    ensure!(
        matches!(index.version, LEGACY_INDEX_VERSION | INDEX_VERSION),
        "unsupported group index version {}",
        index.version
    );
    ensure!(
        storage.resolve(&index.case_source)? == case_source,
        "group index belongs to a different case source"
    );
    for group in &index.groups {
        ensure!(
            storage.resolve(&group.manifest)? == output
                && storage.resolve(&group.report_path)? == output,
            "group {} references a different manifest or report path",
            group.group_id
        );
    }
    validate_index(index, storage, case_source, cases)
}

pub(super) fn case_inventory_id(
    index: &CaseGroupIndex,
    case_source: &Path,
    cases: &[PublishedCase],
) -> Result<String> {
    if index.version == LEGACY_INDEX_VERSION {
        Ok(inventory_id(cases))
    } else {
        portable_inventory_id(case_source, cases)
    }
}

pub(super) fn reject_membership_overlap(
    groups: &[CaseGroupRecord],
    case_ids: &[String],
) -> Result<()> {
    for group in groups {
        ensure!(
            !case_ids.iter().any(|id| group.case_ids.contains(id)),
            "new group overlaps case ids owned by {}",
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
    path_patterns_overlap(left, right)
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
