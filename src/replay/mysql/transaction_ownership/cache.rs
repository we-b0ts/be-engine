//! Disposable proof outcomes bound to every original Source file, without payloads.
use super::*;

const VERSION: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Binding {
    manifest_stamp: FileStamp,
    manifest_sha256: String,
    files: BTreeMap<PathBuf, (FileStamp, String)>,
}

impl Binding {
    pub(super) fn stamp(&self, relative: &Path) -> Result<&FileStamp> {
        self.files
            .get(relative)
            .map(|(stamp, _)| stamp)
            .context("cached MySQL transaction file is missing from its Source binding")
    }

    pub(super) fn read(root: &Path, facts: &Facts) -> Result<Self> {
        let manifest = root.join("recording-run.json");
        let manifest_stamp = FileStamp::read(&manifest)?;
        let manifest_sha256 = crate::policy_evidence::digest(&std::fs::read(&manifest)?);
        let files = facts
            .files
            .iter()
            .map(|file| (file.path.clone(), (file.stamp.clone(), file.sha256.clone())))
            .collect();
        let binding = Self {
            manifest_stamp,
            manifest_sha256,
            files,
        };
        binding.validate(root)?;
        Ok(binding)
    }

    pub(super) fn validate(&self, root: &Path) -> Result<()> {
        ensure!(
            FileStamp::read(&root.join("recording-run.json"))? == self.manifest_stamp
                && self.files.iter().all(|(path, (stamp, _))| {
                    FileStamp::read(&root.join(path)).is_ok_and(|actual| actual == *stamp)
                }),
            "Source changed during MySQL Global transaction preparation"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct Cached {
    version: u32,
    binding: Binding,
    // Omitting a rejected candidate caches that outcome too. Only the complete
    // immutable file inventory may reuse either positive or negative results.
    proofs: Vec<Proof>,
}

pub(super) fn load(
    path: &Path,
    root: &Path,
    cases: &[PathBuf],
) -> Result<Option<(Binding, Vec<Proof>)>> {
    let cached: Cached = match store::read_json(path) {
        Ok(cached) => cached,
        Err(_) => return Ok(None),
    };
    if cached.version != VERSION {
        return Ok(None);
    }
    let mut paths = cases
        .iter()
        .map(|path| path.strip_prefix(root).map(Path::to_owned))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    paths.push(PathBuf::from("global-dependencies.jsonl"));
    paths.sort();
    if !cached.binding.files.keys().eq(paths.iter()) || cached.binding.validate(root).is_err() {
        return Ok(None);
    }
    Ok(Some((cached.binding, cached.proofs)))
}

pub(super) fn save(path: &Path, binding: &Binding, proofs: &[Proof]) -> Result<()> {
    store::write_json(
        path,
        &Cached {
            version: VERSION,
            binding: binding.clone(),
            proofs: proofs.to_vec(),
        },
    )
}
