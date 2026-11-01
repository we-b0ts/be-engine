//! Refresh portable indexes after final append and metadata-only chown.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    artifact_owner::ArtifactOwner,
    dependency_index::{
        FRAGMENT, FileIndex, FileStamp, RecordStream,
        global::{GLOBAL_FRAGMENT, GlobalIndex},
        scoped, store,
    },
};

#[derive(Clone, Copy)]
enum Kind {
    File,
    Global,
}

enum Index {
    File(FileIndex),
    Global(GlobalIndex),
}

impl Index {
    fn read(path: &Path, kind: Kind) -> Result<Self> {
        Ok(match kind {
            Kind::File => Self::File(store::read_json(path)?),
            Kind::Global => Self::Global(store::read_json(path)?),
        })
    }
    fn stamp(&self) -> &FileStamp {
        match self {
            Self::File(index) => &index.stamp,
            Self::Global(index) => &index.stamp,
        }
    }
    fn digest(&self) -> &str {
        match self {
            Self::File(index) => &index.sha256,
            Self::Global(index) => &index.sha256,
        }
    }
    fn publish(mut self, path: &Path, stamp: FileStamp, owner: ArtifactOwner) -> Result<()> {
        let written = match &mut self {
            Self::File(index) => {
                index.stamp = stamp;
                store::write_json(path, index)
            }
            Self::Global(index) => {
                index.stamp = stamp;
                store::write_json(path, index)
            }
        };
        // Atomic replacement creates a fresh inode. Assign it immediately,
        // including when publication reports a later durability failure.
        let assigned = owner.assign_path_to(path);
        written?;
        assigned
    }
}

struct Refresh {
    path: PathBuf,
    dependency: PathBuf,
    kind: Kind,
    fragment_stamp: FileStamp,
    ledger_stamp: FileStamp,
    source: scoped::Source,
    digest: String,
}

impl Refresh {
    fn inspect(path: PathBuf, dependency: PathBuf, kind: Kind) -> Result<Self> {
        let fragment_stamp = FileStamp::read_native(&path)?;
        let index = Index::read(&path, kind)?;
        let source = scoped::resolve(&dependency)?;
        let ledger_stamp = FileStamp::read_native(&source.path)?;
        let previous = index.stamp();
        if source.locations.is_some() {
            // Published Case scopes can freeze before later Cases append to
            // this same central ledger. They are not whole-file snapshots.
            ensure!(
                previous.device == ledger_stamp.device
                    && previous.inode == ledger_stamp.inode
                    && previous.size <= ledger_stamp.size,
                "scoped dependency ledger was replaced or truncated during artifact ownership assignment"
            );
        } else {
            let mut previous = previous.clone();
            previous.changed = ledger_stamp.changed;
            ensure!(
                previous == ledger_stamp,
                "dependency bytes changed during artifact ownership assignment"
            );
        }
        let result = Self {
            path,
            dependency,
            kind,
            fragment_stamp,
            ledger_stamp,
            source,
            digest: index.digest().into(),
        };
        result.validate_stamps()?;
        Ok(result)
    }

    fn validate_stamps(&self) -> Result<()> {
        ensure!(
            FileStamp::read_native(&self.path)? == self.fragment_stamp,
            "dependency fragment changed during artifact ownership assignment"
        );
        ensure!(
            FileStamp::read_native(&self.source.path)? == self.ledger_stamp,
            "dependency bytes changed during artifact ownership assignment"
        );
        self.source.validate()
    }

    fn validate_content(&self) -> Result<()> {
        self.validate_stamps()?;
        let mut input = RecordStream::open(&self.dependency)?;
        ensure!(
            input.stamp == self.ledger_stamp,
            "dependency ledger changed before fragment validation"
        );
        let mut digest = Sha256::new();
        // RecordStream authenticates each selected record against its frozen
        // scope location. The aggregate also proves the original scope has
        // neither gained nor lost records since this index was constructed.
        while let Some((_, bytes)) = input.next()? {
            digest.update(bytes);
        }
        ensure!(
            format!("{:x}", digest.finalize()) == self.digest,
            "dependency scope content changed during artifact ownership assignment"
        );
        self.validate_stamps()
    }
}

fn fragments(root: &Path) -> Result<Vec<Refresh>> {
    let mut pending = vec![root.to_owned()];
    let mut found = Vec::new();
    while let Some(dir) = pending.pop() {
        for (dependency, fragment, kind) in [
            ("dependencies.jsonl", FRAGMENT, Kind::File),
            (
                "global-dependencies.jsonl",
                ".global-dependency-index.json",
                Kind::File,
            ),
            ("global-dependencies.jsonl", GLOBAL_FRAGMENT, Kind::Global),
        ] {
            let path = dir.join(fragment);
            if path.is_file() {
                found.push(Refresh::inspect(path, dir.join(dependency), kind)?);
            }
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    found.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(found)
}

pub(crate) async fn refresh_owned_dependency_indexes(
    root: &Path,
    owner: ArtifactOwner,
) -> Result<()> {
    let root = root.to_owned();
    tokio::task::spawn_blocking(move || {
        let fragments = fragments(&root)?;
        if fragments
            .iter()
            .any(|fragment| fragment.source.locations.is_some())
        {
            // One final seal authenticates the complete ledger and all frozen
            // scope files, including bytes outside an individual Case scope.
            crate::dependency_index::recording::authenticate(&root)?;
        }
        // Validate every candidate before rewriting any fragment. A later bad
        // scope cannot leave an earlier replacement inode owned by the engine.
        for fragment in &fragments {
            fragment.validate_content()?;
        }
        for fragment in fragments {
            fragment.validate_stamps()?;
            Index::read(&fragment.path, fragment.kind)?.publish(
                &fragment.path,
                fragment.ledger_stamp,
                owner,
            )?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("dependency fragment ownership refresh failed")?
}

#[cfg(test)]
mod tests;
