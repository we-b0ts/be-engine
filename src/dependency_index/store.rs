use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::build::{build_file, digest};
use super::model::*;

/// The same completed standard-run boundary for all indexed protocol queries.
pub(crate) fn recording_files(source: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    let source = fs::canonicalize(source)?;
    let root = source
        .ancestors()
        .find(|p| p.join("recording-run.json").is_file())
        .context("cross-case requires a recording-run.json boundary")?
        .to_path_buf();
    let manifest: Value = serde_json::from_slice(&fs::read(root.join("recording-run.json"))?)?;
    ensure!(
        manifest["status"] == "completed",
        "cross-case requires a completed standard recording run"
    );
    crate::case_kind::reject_comparison_recording(&root)?;
    let mut pending = vec![root.clone()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        if dir != root && dir.join("recording-run.json").exists() {
            continue;
        }
        let file = dir.join("dependencies.jsonl");
        if file.is_file() {
            FileStamp::read(&file)?;
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
            if !name.starts_with('.') && !matches!(&*name, "failed" | "staging") {
                pending.push(entry.path());
            }
        }
    }
    files.sort();
    let mut ids = BTreeSet::new();
    for file in &files {
        ensure!(ids.insert(case_id(file)?), "duplicate cross-case case id");
    }
    Ok((root, files))
}

fn case_id(path: &Path) -> Result<String> {
    Ok(path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .context("dependency file has no case identity")?
        .into())
}

pub(crate) fn cache_directory(root: &Path) -> PathBuf {
    // Completed evidence stays immutable. New Recorder fragments are sealed before
    // publication; run indexes and legacy fragments live outside that evidence.
    let parent = root
        .ancestors()
        .find(|p| p.file_name().is_some_and(|name| name == ".traffic-e2e"));
    let storage = parent
        .map(|p| p.join("local/dependency-index"))
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("traffic-e2e-dependency-index-{}", unsafe {
                libc::geteuid()
            }))
        });
    storage.join(digest(root.as_os_str().as_encoded_bytes()))
}

pub(crate) fn load_file(path: &Path) -> Result<FileIndex> {
    load_file_cancellable(path, &std::sync::atomic::AtomicBool::new(false))
}

fn load_file_cancellable(
    path: &Path,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<FileIndex> {
    check_cancelled(cancelled)?;
    let stamp = FileStamp::read(path)?;
    let fragment = path
        .parent()
        .context("dependency file has no parent")?
        .join(FRAGMENT);
    if let Ok(index) = read_json::<FileIndex>(&fragment)
        && index.version == VERSION
        && index.stamp == stamp
    {
        return Ok(index);
    }
    let cache = cache_directory(path);
    private_directory(&cache)?;
    let _lock = Lock::acquire(&cache.join("build.lock"), cancelled)?;
    let output = cache.join("file.json");
    if let Ok(index) = read_json::<FileIndex>(&output)
        && index.version == VERSION
        && index.stamp == stamp
    {
        return Ok(index);
    }
    let index = build_file(path, cancelled)?;
    check_cancelled(cancelled)?;
    write_json(&output, &index)?;
    Ok(index)
}

pub(crate) fn prepare(source: &Path) -> Result<(RunIndex, DependencyIndexReport)> {
    prepare_cancellable(source, &std::sync::atomic::AtomicBool::new(false))
}

fn prepare_cancellable(
    source: &Path,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<(RunIndex, DependencyIndexReport)> {
    check_cancelled(cancelled)?;
    let (root, files) = recording_files(source)?;
    let run: Value = serde_json::from_slice(&fs::read(root.join("recording-run.json"))?)?;
    let run_id = run["run_id"].as_str().unwrap_or_default().to_owned();
    let storage = cache_directory(&root);
    private_directory(&storage)?;
    let _lock = Lock::acquire(&storage.join("build.lock"), cancelled)?;
    let output = storage.join("manifest.json");
    if let Ok(index) = read_json::<RunIndex>(&output)
        && valid_run(&root, &files, &run_id, &index)?
    {
        let report = report("reused", &output, &index);
        return Ok((index, report));
    }
    let started = Instant::now();
    let total_bytes = files
        .iter()
        .map(|p| FileStamp::read(p).map(|m| m.size))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<u64>();
    let mut index = RunIndex {
        version: VERSION,
        run_id,
        files: Vec::new(),
    };
    let mut read_bytes = 0;
    tracing::info!(
        total_files = files.len(),
        total_bytes,
        "preparing dependency index"
    );
    for (position, path) in files.iter().enumerate() {
        let file_index = load_file_cancellable(path, cancelled)?;
        read_bytes += file_index.stamp.size;
        index.files.push(IndexedFile {
            path: path.strip_prefix(&root)?.into(),
            case_id: case_id(path)?,
            index: file_index,
        });
        if position % 100 == 0 || position + 1 == files.len() {
            tracing::info!(
                prepared_files = position + 1,
                total_files = files.len(),
                prepared_bytes = read_bytes,
                total_bytes,
                elapsed_seconds = started.elapsed().as_secs(),
                "preparing dependency index"
            );
        }
    }
    ensure!(
        valid_run(&root, &files, &index.run_id, &index)?,
        "recording changed during dependency index preparation"
    );
    check_cancelled(cancelled)?;
    write_json(&output, &index)?;
    let report = report("built", &output, &index);
    Ok((index, report))
}

fn report(status: &'static str, path: &Path, index: &RunIndex) -> DependencyIndexReport {
    DependencyIndexReport {
        status,
        files: index.files.len(),
        source_bytes: index.files.iter().map(|f| f.index.stamp.size).sum(),
        index_path: path.into(),
    }
}

fn valid_run(root: &Path, files: &[PathBuf], run_id: &str, index: &RunIndex) -> Result<bool> {
    if index.version != VERSION || index.run_id != run_id || index.files.len() != files.len() {
        return Ok(false);
    }
    for (file, indexed) in files.iter().zip(&index.files) {
        if indexed
            .path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
            || root.join(&indexed.path) != *file
            || indexed.index.version != VERSION
            || indexed.index.stamp != FileStamp::read(file)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path)?;
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "refusing linked dependency index directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    FileStamp::read(path)?;
    let bytes = fs::read(path)?;
    let document: Value = serde_json::from_slice(&bytes)?;
    let payload = document
        .get("payload")
        .context("dependency index payload missing")?;
    ensure!(
        document["sha256"] == digest(&serde_json::to_vec(payload)?),
        "dependency index checksum mismatch"
    );
    Ok(serde_json::from_value(payload.clone())?)
}

pub(crate) fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let value = serde_json::to_value(value)?;
    let document =
        serde_json::json!({"sha256": digest(&serde_json::to_vec(&value)?), "payload": value});
    let bytes = serde_json::to_vec(&document)?;
    let parent = path.parent().context("dependency index has no parent")?;
    let temporary = parent.join(format!(".dependency-index-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

struct Lock(File);
impl Lock {
    fn acquire(path: &Path, cancelled: &std::sync::atomic::AtomicBool) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        loop {
            check_cancelled(cancelled)?;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            ensure!(
                error.raw_os_error() == Some(libc::EWOULDBLOCK),
                "failed to lock dependency index: {error}"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(Self(file))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub(super) fn check_cancelled(cancelled: &std::sync::atomic::AtomicBool) -> Result<()> {
    ensure!(
        !cancelled.load(std::sync::atomic::Ordering::Relaxed),
        "dependency index preparation cancelled"
    );
    Ok(())
}

/// Dropping this future cancels the blocking builder, including lock waits.
pub(crate) async fn prepare_with_timeout(
    source: std::path::PathBuf,
    seconds: u64,
) -> Result<DependencyIndexReport> {
    struct Cancel(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Cancel {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let cancel = Cancel(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        false,
    )));
    let flag = cancel.0.clone();
    let task = tokio::task::spawn_blocking(move || {
        prepare_cancellable(&source, &flag).map(|(_, report)| report)
    });
    let report = tokio::time::timeout(std::time::Duration::from_secs(seconds), task)
        .await
        .with_context(|| {
            format!(
                "dependency index preparation exceeded {seconds}s; Replay readiness has not started"
            )
        })?
        .context("dependency index builder failed")??;
    tracing::info!(
        status = report.status,
        files = report.files,
        source_bytes = report.source_bytes,
        "dependency index ready"
    );
    Ok(report)
}
