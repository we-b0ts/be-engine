//! Bounded traversal restricted to one completed standard recording.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(in crate::replay) fn files(source: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    let source = fs::canonicalize(source)?;
    let root = source
        .ancestors()
        .find(|p| p.join("recording-run.json").is_file())
        .context("cross-case requires a recording-run.json boundary")?
        .to_path_buf();
    let run: Value = serde_json::from_slice(&fs::read(root.join("recording-run.json"))?)?;
    ensure!(
        run["status"] == "completed",
        "cross-case requires a completed standard recording run"
    );
    crate::case_kind::reject_comparison_recording(&root)?;
    let mut pending = vec![root.clone()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        if dir != root && dir.join("recording-run.json").exists() {
            continue;
        }
        if dir.join("dependencies.jsonl").is_file() {
            let file = dir.join("dependencies.jsonl");
            ensure!(
                !fs::symlink_metadata(&file)?.file_type().is_symlink(),
                "cross-case refuses linked evidence"
            );
            files.push(file);
            continue;
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || matches!(&*name, "failed" | "staging") {
                continue;
            }
            pending.push(entry.path());
        }
    }
    files.sort();
    let mut ids = std::collections::BTreeSet::new();
    for file in &files {
        ensure!(ids.insert(case_id(file)?), "duplicate cross-case case id");
    }
    Ok((root, files))
}

pub(in crate::replay) fn case_id(file: &Path) -> Result<String> {
    Ok(file
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .context("recorded case has no identity")?
        .to_string())
}
