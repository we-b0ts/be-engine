//! Complete Source content identities reused across rule transactions.
//! Protocol owners still validate every selected original record.
use super::{FileStamp, store};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const VERSION: u32 = 1;
const FRAGMENT: &str = ".source-proof-index.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub path: PathBuf,
    pub digest: String,
    pub files: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Content {
    stamp: FileStamp,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Catalog {
    version: u32,
    run_id: String,
    files: BTreeMap<PathBuf, Content>,
}

pub fn prepare(root: &Path) -> Result<Snapshot> {
    if super::recording::root(root).is_some() {
        return prepare_central(root);
    }
    let (root, files) = legacy_stamps(root)?;
    let run: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("recording-run.json"))?)?;
    let run_id = run["run_id"].as_str().unwrap_or_default().to_owned();
    let directory = store::cache_directory(&root);
    store::private_directory(&directory)?;
    let output = directory.join("source-proof-v1.json");
    let old = [output.clone(), root.join(FRAGMENT)]
        .into_iter()
        .find_map(|path| {
            store::read_json::<Catalog>(&path)
                .ok()
                .filter(|catalog| catalog.version == VERSION && catalog.run_id == run_id)
        });
    if let Some(old) = &old
        && old.files.len() == files.len()
        && files.iter().all(|(path, stamp)| {
            old.files
                .get(path)
                .is_some_and(|value| value.stamp == *stamp)
        })
    {
        // Retain an already sealed Recorder catalog in private storage once.
        if store::read_json::<Catalog>(&output)
            .ok()
            .is_none_or(|current| {
                current.version != old.version
                    || current.run_id != old.run_id
                    || current.files != old.files
            })
        {
            store::write_json(&output, old)?;
        }
        return snapshot(&output, old);
    }
    let mut contents = BTreeMap::new();
    for (relative, stamp) in files {
        let path = root.join(&relative);
        let sha256 = if let Some(previous) = old
            .as_ref()
            .and_then(|old| old.files.get(&relative))
            .filter(|old| old.stamp == stamp)
        {
            previous.sha256.clone()
        } else if relative
            .file_name()
            .is_some_and(|name| name == "dependencies.jsonl")
        {
            super::load_file(&path)?.sha256
        } else if relative == Path::new("global-dependencies.jsonl") {
            super::global::load_global_index(&path, |_| Ok(()))?
                .0
                .sha256
        } else {
            hash_file(&path, &stamp)?
        };
        ensure!(
            FileStamp::read(&path)? == stamp,
            "Source evidence changed during catalog preparation"
        );
        contents.insert(relative, Content { stamp, sha256 });
    }
    let catalog = Catalog {
        version: VERSION,
        run_id,
        files: contents,
    };
    store::write_json(&output, &catalog)?;
    snapshot(&output, &catalog)
}

fn legacy_stamps(root: &Path) -> Result<(PathBuf, BTreeMap<PathBuf, FileStamp>)> {
    let (root, dependencies) = store::recording_files(root)?;
    let mut files = BTreeMap::new();
    files.insert(
        PathBuf::from("recording-run.json"),
        FileStamp::read(&root.join("recording-run.json"))?,
    );
    for dependency in &dependencies {
        for path in [
            dependency.clone(),
            dependency.with_file_name("request.json"),
            dependency.with_file_name("expected-response.json"),
        ] {
            files.insert(
                path.strip_prefix(&root)?.to_path_buf(),
                FileStamp::read(&path).with_context(|| {
                    format!("Source case lacks complete evidence: {}", path.display())
                })?,
            );
        }
    }
    let global = root.join("global-dependencies.jsonl");
    if global.exists() {
        files.insert(
            PathBuf::from("global-dependencies.jsonl"),
            FileStamp::read(&global)?,
        );
    }
    ensure!(
        files.len() <= 400_002,
        "Source proof file inventory exceeds bounds"
    );
    Ok((root, files))
}

/// The plan already authenticated the catalog. Recheck its identity and the
/// filesystem stamps without reading the recorded dependency payloads again.
pub fn verify_frozen(
    root: &Path,
    expected: &Snapshot,
    validation: std::time::SystemTime,
) -> Result<()> {
    let catalog: Catalog = store::read_json(&expected.path)?;
    ensure!(
        snapshot(&expected.path, &catalog)? == *expected,
        "frozen Source proof catalog changed"
    );
    let root = if let Some(root) = super::recording::root(root) {
        root
    } else {
        let (root, files) = legacy_stamps(root)?;
        ensure!(
            files.keys().eq(catalog.files.keys()),
            "complete Source case membership changed after planning"
        );
        root
    };
    for (relative, content) in &catalog.files {
        let path = root.join(relative);
        ensure!(
            FileStamp::read_native(&path)? == content.stamp
                && (content.stamp.stable_before(validation)
                    || hash_file(&path, &content.stamp)? == content.sha256),
            "complete Source evidence changed after planning"
        );
    }
    Ok(())
}

fn prepare_central(path: &Path) -> Result<Snapshot> {
    let (root, manifest) = super::recording::manifest(path)?;
    super::recording::authenticate(&root)?;
    let directory = store::cache_directory(&root);
    store::private_directory(&directory)?;
    let output = directory.join("source-proof-central-v3.json");
    let mut contents = BTreeMap::new();
    for identity in &manifest.files {
        let relative = PathBuf::from(&identity.path);
        contents.insert(
            relative.clone(),
            Content {
                stamp: FileStamp::read_native(&root.join(&relative))?,
                sha256: identity.sha256.trim_start_matches("sha256:").into(),
            },
        );
    }
    let path = root.join(crate::dependency::observation::MANIFEST_FILE);
    let stamp = FileStamp::read_native(&path)?;
    contents.insert(
        PathBuf::from(crate::dependency::observation::MANIFEST_FILE),
        Content {
            sha256: hash_file(&path, &stamp)?,
            stamp,
        },
    );
    let catalog = Catalog {
        version: VERSION,
        run_id: manifest.run_id,
        files: contents,
    };
    if store::read_json::<Catalog>(&output).is_ok_and(|old| {
        old.version == catalog.version && old.run_id == catalog.run_id && old.files == catalog.files
    }) {
        return snapshot(&output, &catalog);
    }
    store::write_json(&output, &catalog)?;
    snapshot(&output, &catalog)
}

fn snapshot(path: &Path, catalog: &Catalog) -> Result<Snapshot> {
    Ok(Snapshot {
        path: path.into(),
        digest: format!("sha256:{:x}", Sha256::digest(serde_json::to_vec(catalog)?)),
        files: catalog.files.len(),
    })
}

fn hash_file(path: &Path, stamp: &FileStamp) -> Result<String> {
    #[cfg(test)]
    HASHED_BYTES.with(|bytes| bytes.set(bytes.get() + stamp.size));
    let mut input = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut size = 0;
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        size += n as u64;
    }
    ensure!(
        size == stamp.size && FileStamp::read_native(path)? == *stamp,
        "Source evidence changed while hashing: {}",
        path.display()
    );
    Ok(format!("{:x}", hash.finalize()))
}

/// Recorder invokes this after its final manifest and ownership assignment.
pub fn seal(root: &Path) -> Result<PathBuf> {
    let snapshot = prepare(root)?;
    let catalog: Catalog = store::read_json(&snapshot.path)?;
    let path = root.join(FRAGMENT);
    store::write_json(&path, &catalog)?;
    Ok(path)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
thread_local! { static HASHED_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
