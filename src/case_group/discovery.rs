use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use super::{normalize_route, validate_single_line};

const IGNORED_DIRECTORIES: &[&str] = &["failed", "staging", ".replay", ".partial", ".truncated"];

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    method: String,
    uri: String,
}

#[derive(Debug, Clone)]
struct RawCase {
    id: String,
    dir: PathBuf,
    method: String,
    path: String,
}

#[derive(Debug, Clone)]
pub(super) struct PublishedCase {
    pub(super) id: String,
    pub(super) dir: PathBuf,
    pub(super) member_dir: PathBuf,
    pub(super) method: String,
    pub(super) path: String,
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
            })
        })
        .collect()
}

fn walk_case_directories(root: &Path, directory: &Path, cases: &mut Vec<RawCase>) -> Result<()> {
    if directory != root && ignored_directory(directory) {
        return Ok(());
    }
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
    let selected = if let Some(pattern) = pattern {
        cases
            .iter()
            .filter(|case| case.method == method && pattern_matches(pattern, &case.path))
            .cloned()
            .collect::<Vec<_>>()
    } else {
        cases
            .iter()
            .filter(|case| case.member_dir == current_dir)
            .cloned()
            .collect::<Vec<_>>()
    };
    ensure!(
        !selected.is_empty(),
        "route selection matched no published cases"
    );
    ensure!(
        selected.iter().any(|case| case.member_dir == current_dir),
        "route selection does not include current case directory {}",
        current_dir.display()
    );
    let members = selected
        .iter()
        .map(|case| case.member_dir.clone())
        .collect::<BTreeSet<_>>();
    for member in members {
        let all_member_cases = cases.iter().filter(|case| case.member_dir == member);
        for case in all_member_cases {
            let matches = case.method == method
                && pattern.map_or(case.path == source_route, |value| {
                    pattern_matches(value, &case.path)
                });
            ensure!(
                matches,
                "mixed-route directory {} contains case {} with {} {}",
                member.display(),
                case.id,
                case.method,
                case.path
            );
        }
    }
    let mut selected = selected;
    selected.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(selected)
}

fn pattern_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.split('/').collect::<Vec<_>>();
    let path = path.split('/').collect::<Vec<_>>();
    pattern.len() == path.len()
        && pattern
            .iter()
            .zip(path)
            .all(|(expected, actual)| *expected == "*" || *expected == actual)
}

pub(super) fn inventory_id(cases: &[PublishedCase]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for case in cases {
        for value in [
            case.id.as_bytes(),
            case.dir.as_os_str().as_encoded_bytes(),
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
    }
    format!("fnv1a64:{hash:016x}")
}
