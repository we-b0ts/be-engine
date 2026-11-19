//! Portable indexes for the original scopes of a sealed recording.
use super::{FileStamp, GlobalIndex, VERSION, build_index_with_evidence, store};
use crate::source::{digest, recording, scoped};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use traffic_model::recording::MANIFEST_FILE;

const PACKAGED_SCOPES: [&str; 2] = ["startup", "process"];
const INDEX_FILE: &str = "index.json";

#[derive(Serialize, Deserialize)]
struct SealedIndex {
    manifest_sha256: String,
    scope: String,
    scope_stamp: FileStamp,
    index: GlobalIndex,
}

pub fn seal_recording_scopes_with_evidence(
    run: &Path,
    validate: impl Fn(&Value) -> Result<()>,
    evidence: &traffic_protocol::evidence::EvidenceRegistry,
) -> Result<()> {
    let revisions: std::collections::BTreeMap<String, String> = evidence
        .revisions()
        .into_iter()
        .map(|(name, revision)| (name.to_owned(), revision.to_owned()))
        .collect();
    let (run, _) = recording::manifest(run)?;
    let manifest_path = run.join(MANIFEST_FILE);
    let manifest_stamp = FileStamp::read_native(&manifest_path)?;
    let manifest_sha256 = digest(&std::fs::read(&manifest_path)?);
    let indexes = run.join("indexes");
    let stamp = FileStamp::read_native(&recording::dependency_path(&run))?;
    let cancelled = AtomicBool::new(false);
    for scope in PACKAGED_SCOPES {
        let view = indexes.join(format!("{scope}-scope.json"));
        if load(&view, &stamp, true).is_some_and(|(index, _)| index.providers == revisions) {
            continue;
        }
        let scope_stamp = FileStamp::read(&view)?;
        let output = indexes.join(format!("{scope}-dependencies"));
        store::private_directory(&output)?;
        let index = build_index_with_evidence(
            &view, &output, &stamp, &validate, &cancelled, evidence, true,
        )?;
        ensure!(
            FileStamp::read(&view)? == scope_stamp
                && FileStamp::read_native(&manifest_path)? == manifest_stamp,
            "recording scope or manifest changed during index publication"
        );
        store::write_json(
            &output.join(INDEX_FILE),
            &SealedIndex {
                manifest_sha256: manifest_sha256.clone(),
                scope: scope.into(),
                scope_stamp,
                index,
            },
        )?;
    }
    Ok(())
}

pub(super) fn load(path: &Path, stamp: &FileStamp, verify: bool) -> Option<(GlobalIndex, PathBuf)> {
    let view = scoped::view_path(path)?;
    let indexes = view.parent()?;
    let run = indexes.parent()?;
    // An effective attribution view can have the same filename. Only the
    // original recording scopes may consume the packaged indexes.
    if indexes.file_name()?.to_str()? != "indexes" {
        return None;
    }
    let name = view.file_name()?.to_str()?;
    let scope = name
        .strip_suffix("-scope.bin")
        .or_else(|| name.strip_suffix("-scope.json"))?;
    if !PACKAGED_SCOPES.contains(&scope) {
        return None;
    }
    let output = indexes.join(format!("{scope}-dependencies"));
    if !std::fs::symlink_metadata(&output).ok()?.is_dir() {
        return None;
    }
    let mut sealed: SealedIndex = store::read_json(&output.join(INDEX_FILE)).ok()?;
    let manifest = run.join(MANIFEST_FILE);
    let manifest_stamp = FileStamp::read_native(&manifest).ok()?;
    let scope_stamp = FileStamp::read_native(&view).ok()?;
    if sealed.scope != scope
        || sealed.index.version != VERSION
        || sealed.index.stamp.size != stamp.size
        || sealed.manifest_sha256 != digest(&std::fs::read(&manifest).ok()?)
    {
        return None;
    }
    // Copies and Recorder ownership assignment can change the filesystem
    // stamps. Authenticate against the same sealed manifest before rebinding.
    if verify && (sealed.index.stamp != *stamp || sealed.scope_stamp != scope_stamp) {
        recording::authenticate(run).ok()?;
    }
    if verify
        && (FileStamp::read_native(&manifest).ok()? != manifest_stamp
            || FileStamp::read_native(&view).ok()? != scope_stamp
            || FileStamp::read_native(&recording::dependency_path(run)).ok()? != *stamp)
    {
        return None;
    }
    sealed.index.records.validate_files(&output).ok()?;
    for lane in &sealed.index.notifications {
        lane.pages.validate_files(&output).ok()?;
    }
    sealed.index.stamp = stamp.clone();
    Some((sealed.index, output))
}
