use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::path_pattern::matches_path_pattern;

use super::{normalize_route, validate_single_line};

const IGNORED_DIRECTORIES: &[&str] = &["failed", "staging", ".replay", ".partial", ".truncated"];

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    #[serde(default)]
    timestamp: Option<DateTime<Utc>>,
    method: String,
    uri: String,
    #[serde(default)]
    api_pattern: Option<String>,
}

#[derive(Debug, Clone)]
struct RawCase {
    id: String,
    dir: PathBuf,
    method: String,
    path: String,
    recorded_at: Option<DateTime<Utc>>,
    has_recording_api_pattern: bool,
}

#[derive(Debug, Clone)]
pub(super) struct PublishedCase {
    pub(super) id: String,
    pub(super) dir: PathBuf,
    pub(super) member_dir: PathBuf,
    pub(super) method: String,
    pub(super) path: String,
    pub(super) recorded_at: Option<DateTime<Utc>>,
}

pub(super) fn discover_published_cases(case_source: &Path) -> Result<Vec<PublishedCase>> {
    ensure!(
        !ignored_directory(case_source),
        "case source {} is an ignored or incomplete artifact directory",
        case_source.display()
    );
    let mut raw = Vec::new();
    walk_case_directories(case_source, case_source, &mut raw)?;
    raw.sort_by(|left, right| left.dir.cmp(&right.dir));
    let direct_collection = raw.iter().any(|case| {
        case.dir
            .strip_prefix(case_source)
            .is_ok_and(|relative| relative.components().count() <= 1)
    });
    if direct_collection {
        ensure!(
            raw.iter().all(|case| case
                .dir
                .strip_prefix(case_source)
                .is_ok_and(|relative| relative.components().count() <= 1)),
            "case source mixes direct cases with nested case groups"
        );
    }
    raw.into_iter()
        .map(|case| {
            let member_dir = if direct_collection {
                case_source.to_path_buf()
            } else if case.has_recording_api_pattern {
                case.dir
                    .parent()
                    .context("recorded API case has no member directory")?
                    .to_path_buf()
            } else {
                let relative = case.dir.strip_prefix(case_source)?;
                let first = relative
                    .components()
                    .next()
                    .context("published case has no directory below case source")?;
                case_source.join(first.as_os_str())
            };
            Ok(PublishedCase {
                id: case.id,
                dir: case.dir,
                member_dir,
                method: case.method,
                path: case.path,
                recorded_at: case.recorded_at,
            })
        })
        .collect()
}

fn walk_case_directories(root: &Path, directory: &Path, cases: &mut Vec<RawCase>) -> Result<()> {
    if directory != root && ignored_directory(directory) {
        return Ok(());
    }
    crate::case_kind::reject_comparison_recording(directory)?;
    let request = directory.join("request.json");
    let expected_hyphen = directory.join("expected-response.json");
    let expected_underscore = directory.join("expected_response.json");
    let has_request = request.is_file();
    let has_expected = expected_hyphen.is_file() || expected_underscore.is_file();
    if has_request || has_expected {
        ensure!(
            has_request && has_expected,
            "incomplete published case directory {}",
            directory.display()
        );
        let payload =
            fs::read(&request).with_context(|| format!("failed to read {}", request.display()))?;
        let recorded: RecordedRequest = serde_json::from_slice(&payload)
            .with_context(|| format!("failed to parse {}", request.display()))?;
        validate_single_line("recorded request method", &recorded.method)?;
        if let Some(pattern) = &recorded.api_pattern {
            validate_single_line("recorded API pattern", pattern)?;
        }
        let path = request_path(&recorded.uri)?;
        let id = directory
            .file_name()
            .and_then(|name| name.to_str())
            .context("case id is not valid UTF-8")?
            .to_string();
        cases.push(RawCase {
            id,
            dir: directory.to_path_buf(),
            method: recorded.method.trim().to_ascii_uppercase(),
            path,
            recorded_at: recorded.timestamp,
            has_recording_api_pattern: recorded.api_pattern.is_some(),
        });
        return Ok(());
    }
    let mut children = fs::read_dir(directory)
        .with_context(|| format!("failed to read case directory {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        if child.file_type()?.is_dir() {
            walk_case_directories(root, &child.path(), cases)?;
        }
    }
    Ok(())
}

fn ignored_directory(directory: &Path) -> bool {
    directory
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            IGNORED_DIRECTORIES.contains(&name)
                || name.ends_with(".partial")
                || name.ends_with(".truncated")
        })
}

fn request_path(uri: &str) -> Result<String> {
    validate_single_line("recorded request URI", uri)?;
    let end = uri.find(['?', '#']).unwrap_or(uri.len());
    normalize_route(&uri[..end], "recorded request path")
}

pub(super) fn reject_duplicate_case_ids(cases: &[PublishedCase]) -> Result<()> {
    let mut owners = BTreeMap::new();
    for case in cases {
        if let Some(existing) = owners.insert(&case.id, &case.dir) {
            bail!(
                "duplicate case id {} in {} and {}",
                case.id,
                existing.display(),
                case.dir.display()
            );
        }
    }
    Ok(())
}

pub(super) fn resolve_member_dir(requested: &Path, cases: &[PublishedCase]) -> Result<PathBuf> {
    let members = cases
        .iter()
        .map(|case| case.member_dir.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        members.contains(requested),
        "case directory {} is not a canonical input group; expected one of: {}",
        requested.display(),
        members
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(requested.to_path_buf())
}

pub(super) fn select_group_cases(
    cases: &[PublishedCase],
    current_dir: &Path,
    method: &str,
    source_route: &str,
    pattern: Option<&str>,
) -> Result<Vec<PublishedCase>> {
    // Membership belongs to cases, not physical directories. Recorder folders
    // are path-based and may contain several HTTP methods.
    let selected = cases
        .iter()
        .filter(|case| {
            case.method == method
                && pattern.map_or(case.path == source_route, |value| {
                    matches_path_pattern(value, &case.path)
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        !selected.is_empty(),
        "route selection matched no published cases"
    );
    ensure!(
        selected.iter().any(|case| case.member_dir == current_dir),
        "route selection does not include current case directory {}",
        current_dir.display()
    );
    let mut selected = selected;
    selected.sort_by(|left, right| {
        left.recorded_at
            .cmp(&right.recorded_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(selected)
}

pub(super) fn inventory_id(cases: &[PublishedCase]) -> String {
    inventory_id_with_paths(cases.iter().map(|case| case.dir.as_path()), cases)
}

pub(super) fn portable_inventory_id(case_source: &Path, cases: &[PublishedCase]) -> Result<String> {
    let relative_paths = cases
        .iter()
        .map(|case| {
            case.dir.strip_prefix(case_source).with_context(|| {
                format!(
                    "published case {} is outside case source {}",
                    case.dir.display(),
                    case_source.display()
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(inventory_id_with_paths(relative_paths, cases))
}

fn inventory_id_with_paths<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
    cases: &[PublishedCase],
) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for (case, path) in cases.iter().zip(paths) {
        for value in [
            case.id.as_bytes(),
            path.as_os_str().as_encoded_bytes(),
            case.method.as_bytes(),
            case.path.as_bytes(),
        ] {
            for byte in value {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x100000001b3);
            }
            hash ^= 0xff;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        if let Some(recorded_at) = case.recorded_at {
            for byte in recorded_at.to_rfc3339().as_bytes() {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x100000001b3);
            }
            hash ^= 0xfe;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("fnv1a64:{hash:016x}")
}

#[cfg(test)]
mod comparison_recording_tests {
    use super::*;

    #[test]
    fn rejects_comparison_recording_artifacts_explicitly() {
        let root = tempfile::tempdir().unwrap();
        let case = root.path().join("case");
        std::fs::create_dir(&case).unwrap();
        std::fs::write(
            case.join("case-kind.json"),
            r#"{"version":1,"kind":"comparison_recording"}"#,
        )
        .unwrap();
        std::fs::write(case.join("request.json"), r#"{"method":"GET","uri":"/"}"#).unwrap();
        let error = discover_published_cases(root.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("comparison recording artifacts are not replay cases"));
    }
}
