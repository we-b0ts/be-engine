//! Manifest-owned discovery. Directory contents cannot invent Case ownership.
pub use crate::event_index::SourceEventIndex;
use crate::event_index::{self, INDEX, JOURNALS};
use crate::format::{EVENTS, PUSH_EVENTS};
use crate::partitions;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
};
use traffic_model::recording::identity::IdentityKind;
use traffic_model::recording::{
    COMPACT_RECORDING_SCHEMA, MANIFEST_FILE, RECORDING_SCHEMA, RecordingManifest,
};
use traffic_model::trace::{CaptureEvent, RecordedEvent};
use uuid::Uuid;

pub fn supported_recording_schema(schema: &str) -> bool {
    schema == COMPACT_RECORDING_SCHEMA
        || cfg!(any(test, feature = "test-support")) && schema == RECORDING_SCHEMA
}

pub fn dependency_path(root: &Path) -> PathBuf {
    let compact = root.join(partitions::DIRECTORY);
    if compact.exists() {
        compact
    } else {
        root.join("dependencies.jsonl")
    }
}

pub fn root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|p| p.join(MANIFEST_FILE).is_file())
        .map(Path::to_owned)
}

pub fn manifest(path: &Path) -> Result<(PathBuf, RecordingManifest)> {
    let root = root(path).context("recording requires the current central dependency manifest; old recording semantics are unsupported")?;
    let manifest: RecordingManifest = serde_json::from_slice(&fs::read(root.join(MANIFEST_FILE))?)?;
    ensure!(
        supported_recording_schema(&manifest.schema),
        "unsupported recording schema; create a new recording with the current engine"
    );
    ensure!(manifest.sealed, "recording evidence is not sealed");
    ensure!(!manifest.run_id.is_empty(), "recording has no run identity");
    let dependencies = dependency_path(&root);
    ensure!(
        (manifest.schema == COMPACT_RECORDING_SCHEMA) == partitions::is_directory(&dependencies),
        "recording manifest and dependency storage format disagree"
    );
    if manifest.schema == COMPACT_RECORDING_SCHEMA {
        ensure!(
            partitions::recording_id(&dependencies)? == manifest.run_epoch,
            "dependency partition directory belongs to a different recording"
        );
    }
    Ok((root, manifest))
}

pub fn has_separated_messages(path: &Path) -> Result<bool> {
    let (_, manifest) = manifest(path)?;
    Ok(manifest.schema == COMPACT_RECORDING_SCHEMA
        && manifest
            .files
            .iter()
            .any(|file| file.path == partitions::PUSH_DEPENDENCIES && file.length > 0))
}

/// Merge the journals of a sealed recording in original Source order.
pub fn events(path: &Path) -> Result<impl Iterator<Item = Result<RecordedEvent<CaptureEvent>>>> {
    let (root, manifest) = manifest(path)?;
    let compact = manifest.schema == COMPACT_RECORDING_SCHEMA;
    let name = if compact {
        EVENTS
    } else {
        "dependency-lifecycle.jsonl"
    };
    let open = |name| fs::File::open(root.join(name)).map(|file| BufReader::new(file).lines());
    let ordinary = open(name)?;
    let pushes = compact.then(|| open(PUSH_EVENTS)).transpose()?;
    let decode = move |line: std::io::Result<String>| {
        let line = line?;
        if compact {
            crate::event_format::decode_event(&line, manifest.run_epoch)
        } else {
            Ok(serde_json::from_str(&line)?)
        }
    };
    Ok(event_index::merge(
        ordinary.map(decode),
        pushes.into_iter().flatten().map(decode),
        compact,
    ))
}

pub fn event_index(path: &Path) -> Result<Option<SourceEventIndex>> {
    open_event_index(path, true)
}

pub fn event_index_for_replay(path: &Path) -> Result<Option<SourceEventIndex>> {
    open_event_index(path, false)
}

fn open_event_index(path: &Path, verify: bool) -> Result<Option<SourceEventIndex>> {
    let (root, manifest) = manifest(path)?;
    if manifest.schema == COMPACT_RECORDING_SCHEMA {
        let index = if verify {
            SourceEventIndex::open(root, manifest.run_epoch)?
        } else {
            SourceEventIndex::open_for_replay(root, manifest.run_epoch)?
        };
        return Ok(Some(index));
    }
    Ok(None)
}

pub fn cases(path: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    let (root, inputs) = case_inputs(path)?;
    Ok((root, inputs.into_iter().map(|(_, scope)| scope).collect()))
}

/// Original input identities with their validated physical Case scopes.
pub fn case_inputs(path: &Path) -> Result<(PathBuf, Vec<(Uuid, PathBuf)>)> {
    let path = fs::canonicalize(path)?;
    let (root, manifest) = manifest(&path)?;
    let root = fs::canonicalize(root)?;
    let mut paths = Vec::new();
    let mut ids = BTreeSet::new();
    for input in manifest.inputs {
        ensure!(
            ids.insert(input.case_id),
            "recording manifest contains duplicate input identities"
        );
        let relative = Path::new(&input.path);
        ensure!(
            !relative.is_absolute()
                && relative
                    .components()
                    .all(|p| matches!(p, std::path::Component::Normal(_))),
            "recording input escapes its run"
        );
        let directory = root.join(relative);
        if !directory.starts_with(&path) {
            continue;
        }
        if !input.complete {
            ensure!(
                directory != path,
                "selected recording input {} is incomplete",
                input.case_id
            );
            continue;
        }
        let label = IdentityKind::Case.display(manifest.run_epoch, input.case_id);
        ensure!(
            directory.file_name().is_some_and(|n| n == label.as_str()),
            "recording Case directory does not match its identity"
        );
        let scope = super::scoped::case_path(&directory);
        ensure!(
            scope.is_file(),
            "recording Case lacks its declared dependency scope"
        );
        paths.push((input.case_id, scope));
    }
    paths.sort_unstable_by(|left, right| left.1.cmp(&right.1));
    Ok((root, paths))
}

/// Authenticate the immutable run once at preparation, never in request matching.
pub fn authenticate(path: &Path) -> Result<()> {
    let (root, manifest) = manifest(path)?;
    let manifest_path = root.join(MANIFEST_FILE);
    let manifest_stamp = super::FileStamp::read_native(&manifest_path)?;
    let mut stamps = std::collections::BTreeMap::new();
    stamps.insert(PathBuf::from(MANIFEST_FILE), manifest_stamp.clone());
    for file in &manifest.files {
        let relative = Path::new(&file.path);
        ensure!(
            !relative.is_absolute()
                && relative
                    .components()
                    .all(|p| matches!(p, std::path::Component::Normal(_))),
            "recording file identity escapes run"
        );
        stamps.insert(
            relative.to_owned(),
            super::FileStamp::read_native(&root.join(relative))?,
        );
    }
    let cache = super::store::cache_directory(&root);
    super::store::private_directory(&cache)?;
    let authentication = cache.join("authenticated-recording-v3.json");
    if super::store::read_json::<std::collections::BTreeMap<PathBuf, super::FileStamp>>(
        &authentication,
    )
    .is_ok_and(|cached| cached == stamps)
    {
        return Ok(());
    }
    let mut seen = BTreeSet::new();
    for identity in manifest.files {
        let relative = Path::new(&identity.path);
        ensure!(
            !relative.is_absolute()
                && relative
                    .components()
                    .all(|p| matches!(p, std::path::Component::Normal(_))),
            "recording file identity escapes run"
        );
        ensure!(
            seen.insert(identity.path.clone()),
            "duplicate recording file identity"
        );
        let file = root.join(relative);
        let stamp = super::FileStamp::read_native(&file)?;
        ensure!(
            stamp.size == identity.length,
            "sealed recording length changed"
        );
        let mut input = fs::File::open(&file)?;
        let mut hash = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        ensure!(
            format!("{:x}", hash.finalize()) == identity.sha256.trim_start_matches("sha256:"),
            "sealed recording content changed: {}",
            identity.path
        );
        ensure!(
            super::FileStamp::read_native(&file)? == stamp,
            "recording changed during authentication"
        );
    }
    let required = if manifest.schema == COMPACT_RECORDING_SCHEMA {
        partitions::FILES
            .into_iter()
            .chain([
                partitions::DIRECTORY,
                INDEX,
                crate::dependency_columns::FILE,
            ])
            .chain(JOURNALS)
            .collect::<Vec<_>>()
    } else {
        vec!["dependencies.jsonl", "dependency-lifecycle.jsonl"]
    };
    ensure!(
        required.into_iter().all(|name| seen.contains(name)),
        "recording seal omits dependency inventory or lifecycle evidence"
    );
    ensure!(
        super::FileStamp::read_native(&manifest_path)? == manifest_stamp,
        "recording manifest changed during authentication"
    );
    super::store::write_json(&authentication, &stamps)?;
    Ok(())
}
