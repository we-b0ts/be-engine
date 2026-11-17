use super::*;
use sha2::{Digest, Sha256};
use std::{fs, io::Read};

pub(super) fn load(scope: &NativeSourceScope<'_>) -> Result<(NativeSourceInventory, Vec<PathBuf>)> {
    let (root, files) = crate::dependency_index::recording_files(scope.case_source)?;
    let manifest_path = root.join(crate::dependency::observation::MANIFEST_FILE);
    #[cfg(test)]
    let manifest_path = if manifest_path.is_file() {
        manifest_path
    } else {
        root.join("recording-run.json")
    };
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    ensure!(
        manifest["run_id"].as_str() == Some(scope.recording_run_id),
        "Source inventory belongs to a different recording run"
    );
    ensure!(
        root.file_name().and_then(|name| name.to_str()) == Some(scope.recording_run_id),
        "Source recording boundary and run identity differ"
    );
    ensure!(
        files.len() <= 100_000,
        "Source proof case inventory exceeds bounds"
    );
    let snapshot = crate::dependency_index::evidence::prepare(&root)?;
    let artifacts = BTreeSet::from([manifest_path, snapshot.path.clone()]);
    for path in &files {
        for name in ["request.json", "expected-response.json"] {
            let file = path.with_file_name(name);
            ensure!(
                file.is_file(),
                "Source case has no complete {}: {}",
                name,
                path.display()
            );
        }
    }
    for (case, directory) in scope.prepared_cases {
        let expected = fs::canonicalize(prepared_path(directory))?;
        ensure!(
            files.contains(&expected)
                && directory.file_name().and_then(|v| v.to_str()) == Some(case),
            "prepared Case is outside the complete Source recording inventory"
        );
    }
    let mut all = files;
    if let Some(recording) = crate::dependency_index::recording::root(scope.case_source) {
        all.push(recording.join("indexes/startup-scope.json"));
        all.push(recording.join("indexes/process-scope.json"));
        all.push(recording.join("indexes/unattributed-scope.json"));
    } else {
        #[cfg(test)]
        if root.join("global-dependencies.jsonl").is_file() {
            all.push(root.join("global-dependencies.jsonl"));
        }
    }
    Ok((
        NativeSourceInventory {
            recording_root: root,
            recording_run_id: scope.recording_run_id.into(),
            digest: String::new(),
            artifact_paths: artifacts,
            snapshot,
        },
        all,
    ))
}

fn prepared_path(directory: &Path) -> PathBuf {
    #[cfg(test)]
    if !directory
        .join(crate::dependency_index::scoped::CASE_SCOPE)
        .is_file()
    {
        return directory.join("dependencies.jsonl");
    }
    crate::dependency_index::scoped::case_path(directory)
}

pub(super) fn digest(inventory: &NativeSourceInventory) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"traffic-policy/source-inventory/v3\0");
    hash.update(inventory.recording_root.as_os_str().as_encoded_bytes());
    hash.update(inventory.recording_run_id.as_bytes());
    hash.update(inventory.snapshot.digest.as_bytes());
    for path in &inventory.artifact_paths {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "Source proof artifact must be a regular file: {}",
            path.display()
        );
        let name = path.as_os_str().as_encoded_bytes();
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name);
        hash.update(metadata.len().to_be_bytes());
        let mut file = fs::File::open(path)?;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}
