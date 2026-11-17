//! Reuse original Case indexes published with a completed recording.
use super::{
    FRAGMENT, FileIndex, FileStamp, build::digest, model::VERSION, recording, scoped, store,
};
use crate::dependency::observation::{MANIFEST_FILE, RecordingManifest};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

const CATALOG: &str = "indexes/case-dependency-indexes.json";
const SCHEMA: u32 = 1;

#[derive(Deserialize)]
struct Header {
    version: u32,
    stamp: FileStamp,
    scope_membership_sha256: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct CaseSeal {
    scope_sha256: String,
    index_sha256: String,
}

#[derive(Deserialize, Serialize)]
struct Catalog {
    schema: u32,
    manifest_sha256: String,
    ledger: FileStamp,
    cases: BTreeMap<PathBuf, CaseSeal>,
}

struct Current {
    root: PathBuf,
    manifest: FileStamp,
    ledger: FileStamp,
    catalog: FileStamp,
    contents: Arc<Catalog>,
}

pub(crate) fn seal(root: &Path) -> Result<Option<PathBuf>> {
    let (root, manifest) = recording::manifest(root)?;
    let manifest_path = root.join(MANIFEST_FILE);
    let manifest_stamp = FileStamp::read_native(&manifest_path)?;
    let manifest_sha256 = digest(&fs::read(&manifest_path)?);
    let ledger_path = root.join("dependencies.jsonl");
    let ledger = FileStamp::read_native(&ledger_path)?;
    recording::authenticate(&root)?;
    let scopes = scope_digests(&manifest);
    let mut cases = BTreeMap::new();
    for input in manifest.inputs.iter().filter(|input| input.complete) {
        let relative = Path::new(&input.path).join(scoped::CASE_SCOPE);
        let Some(sha256) = relative.to_str().and_then(|path| scopes.get(path)) else {
            continue;
        };
        let fragment = root.join(&relative).with_file_name(FRAGMENT);
        let Ok(bytes) = fs::read(&fragment) else {
            continue;
        };
        let Ok((index, index_sha256)) = store::decode_json::<Header>(&bytes) else {
            continue;
        };
        if index.version != VERSION
            || index.scope_membership_sha256.is_none()
            || index.stamp.device != ledger.device
            || index.stamp.inode != ledger.inode
            || index.stamp.size > ledger.size
        {
            continue;
        }
        let source = scoped::resolve(&root.join(&relative))?;
        if index.scope_membership_sha256 != source.membership_sha256()? {
            continue;
        }
        cases.insert(
            relative,
            CaseSeal {
                scope_sha256: (*sha256).to_owned(),
                index_sha256,
            },
        );
    }
    if cases.is_empty() {
        return Ok(None);
    }
    ensure!(
        FileStamp::read_native(&manifest_path)? == manifest_stamp
            && FileStamp::read_native(&ledger_path)? == ledger,
        "recording changed during Case index publication"
    );
    let output = root.join(CATALOG);
    store::write_json(
        &output,
        &Catalog {
            schema: SCHEMA,
            manifest_sha256,
            ledger,
            cases,
        },
    )?;
    Ok(Some(output))
}

fn scope_digests(manifest: &RecordingManifest) -> BTreeMap<&str, &str> {
    manifest
        .files
        .iter()
        .filter(|file| {
            Path::new(&file.path)
                .file_name()
                .is_some_and(|name| name == scoped::CASE_SCOPE)
        })
        .map(|file| {
            (
                file.path.as_str(),
                file.sha256.trim_start_matches("sha256:"),
            )
        })
        .collect()
}

fn current(root: &Path, ledger: &FileStamp) -> Result<Arc<Catalog>> {
    static CACHE: OnceLock<Mutex<Option<Current>>> = OnceLock::new();
    let catalog_path = root.join(CATALOG);
    let catalog = FileStamp::read_native(&catalog_path)?;
    let manifest_path = root.join(MANIFEST_FILE);
    let manifest = FileStamp::read_native(&manifest_path)?;
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| anyhow::anyhow!("Case index catalog lock poisoned"))?;
    if let Some(cached) = cache.as_ref().filter(|entry| {
        entry.root == root
            && entry.manifest == manifest
            && entry.ledger == *ledger
            && entry.catalog == catalog
    }) {
        return Ok(cached.contents.clone());
    }
    let mut contents: Catalog = store::read_json(&catalog_path)?;
    let bytes = fs::read(&manifest_path)?;
    ensure!(
        contents.schema == SCHEMA && contents.manifest_sha256 == digest(&bytes),
        "Case index catalog belongs to another recording manifest"
    );
    let sealed: RecordingManifest = serde_json::from_slice(&bytes)?;
    ensure!(
        sealed.sealed,
        "Case index catalog requires a sealed recording"
    );
    let scopes = scope_digests(&sealed);
    contents.cases.retain(|path, entry| {
        path.to_str()
            .and_then(|path| scopes.get(path))
            .is_some_and(|sha| *sha == entry.scope_sha256)
    });
    // Recording transfer and metadata-only ownership assignment can change
    // filesystem stamps. Authenticate the ledger once before rebinding.
    if contents.ledger != *ledger {
        recording::authenticate(root)?;
    }
    ensure!(
        FileStamp::read_native(&manifest_path)? == manifest
            && FileStamp::read_native(&catalog_path)? == catalog
            && FileStamp::read_native(&root.join("dependencies.jsonl"))? == *ledger,
        "recording changed while loading its Case index catalog"
    );
    let contents = Arc::new(contents);
    *cache = Some(Current {
        root: root.to_owned(),
        manifest,
        ledger: ledger.clone(),
        catalog,
        contents: contents.clone(),
    });
    Ok(contents)
}

pub(super) fn load(source: &scoped::Source, ledger: &FileStamp) -> Option<FileIndex> {
    let (view, _) = source.view.as_ref()?;
    if view.file_name()? != scoped::CASE_SCOPE {
        return None;
    }
    let root = source.path.parent()?;
    load_original(root, view, source, ledger).ok()
}

fn load_original(
    root: &Path,
    view: &Path,
    source: &scoped::Source,
    ledger: &FileStamp,
) -> Result<FileIndex> {
    let catalog = current(root, ledger)?;
    let canonical = fs::canonicalize(view)?;
    let seal = catalog
        .cases
        .get(canonical.strip_prefix(root)?)
        .context("recording Case index is not packaged for this scope")?;
    let sha256 = source.scope_sha256()?;
    ensure!(
        sha256.as_deref() == Some(seal.scope_sha256.as_str()),
        "packaged Case scope differs"
    );
    let fragment = view.with_file_name(FRAGMENT);
    FileStamp::read_native(&fragment)?;
    let bytes = fs::read(fragment)?;
    let (mut index, index_sha256) = store::decode_json::<FileIndex>(&bytes)?;
    ensure!(
        index_sha256 == seal.index_sha256,
        "packaged Case index content changed"
    );
    ensure!(
        index.version == VERSION
            && index.scope_membership_sha256.is_some()
            && FileStamp::read_native(&source.path)? == *ledger,
        "packaged Case index no longer matches its recording"
    );
    source.validate()?;
    index.stamp = ledger.clone();
    Ok(index)
}

#[cfg(test)]
mod tests;
