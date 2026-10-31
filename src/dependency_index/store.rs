#[cfg(test)]
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
    if let Some(root) = super::recording::root(source) {
        return super::recording::cases(&root);
    }
    #[cfg(not(test))]
    anyhow::bail!(
        "recording requires the current central dependency manifest; old recording semantics are unsupported"
    );
    #[cfg(test)]
    {
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
    let mut identity = root.as_os_str().as_encoded_bytes().to_vec();
    if let Some(view) = super::scoped::view_path(root)
        && let Ok(stamp) = FileStamp::read_native(&view)
    {
        identity.extend(serde_json::to_vec(&stamp).expect("file stamp serializes"));
    }
    storage.join(digest(&identity))
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
    if super::scoped::view_path(path).is_none()
        && let Ok(index) = read_json::<FileIndex>(&fragment)
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

/// Only configured API-origin MySQL discovery requests this optional extension.
pub(crate) fn load_mysql_file(path: &Path) -> Result<FileIndex> {
    let base = load_file(path)?;
    // New Recorder summaries already contain SQL-free MySQL metadata. Legacy
    // fragments alone need the optional extension pass over their original file.
    if base.mysql.is_some() {
        return Ok(base);
    }
    let stamp = base.stamp.clone();
    let directory = cache_directory(path);
    private_directory(&directory)?;
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let _lock = Lock::acquire(&directory.join("build.lock"), &cancelled)?;
    let cache = directory.join("file-mysql-v5.json");
    if let Ok(index) = read_json::<FileIndex>(&cache)
        && index.version == VERSION
        && index.stamp == stamp
        && index.mysql.is_some()
    {
        return Ok(index);
    }
    let index = super::mysql::extend(path, base)?;
    write_json(&cache, &index)?;
    Ok(index)
}

pub(crate) fn prepare(
    source: &Path,
    validate: fn(&Value) -> Result<()>,
) -> Result<(RunIndex, DependencyIndexReport)> {
    prepare_cancellable(source, &std::sync::atomic::AtomicBool::new(false), validate)
}

fn prepare_cancellable(
    source: &Path,
    cancelled: &std::sync::atomic::AtomicBool,
    validate: fn(&Value) -> Result<()>,
) -> Result<(RunIndex, DependencyIndexReport)> {
    check_cancelled(cancelled)?;
    let (root, files) = recording_files(source)?;
    let global = root.join("global-dependencies.jsonl");
    let global_bytes = if super::scoped::exists(&global) {
        super::global::load_global_index_cancellable(&global, validate, cancelled)?
            .0
            .stamp
            .size
    } else {
        0
    };
    let run: Value = serde_json::from_slice(&fs::read(root.join("recording-run.json"))?)?;
    let run_id = run["run_id"].as_str().unwrap_or_default().to_owned();
    let storage = cache_directory(&root);
    private_directory(&storage)?;
    let _lock = Lock::acquire(&storage.join("build.lock"), cancelled)?;
    let output = storage.join("manifest.json");
    if let Ok(index) = read_json::<RunIndex>(&output)
        && valid_run(&root, &files, &run_id, &index)?
    {
        let mut report = report("reused", &output, &index);
        report.global_source_bytes = global_bytes;
        return Ok((index, report));
    }
    let started = Instant::now();
    let total_bytes = files
        .iter()
        .map(|p| super::scoped::selected_bytes(p))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<u64>();
    let mut index = RunIndex {
        version: VERSION,
        run_id,
        files: Vec::new(),
        source_bytes: total_bytes,
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
    let mut report = report("built", &output, &index);
    report.global_source_bytes = global_bytes;
    Ok((index, report))
}

fn report(status: &'static str, path: &Path, index: &RunIndex) -> DependencyIndexReport {
    DependencyIndexReport {
        status,
        files: index.files.len(),
        source_bytes: index.source_bytes,
        index_path: path.into(),
        global_source_bytes: 0,
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

pub(crate) fn private_directory(path: &Path) -> Result<()> {
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
    #[derive(serde::Deserialize)]
    struct Document<'a> {
        #[serde(default)]
        format: Option<&'a str>,
        sha256: &'a str,
        #[serde(borrow)]
        payload: &'a serde_json::value::RawValue,
    }
    FileStamp::read(path)?;
    let bytes = fs::read(path)?;
    let document: Document<'_> = serde_json::from_slice(&bytes)?;
    let actual = match document.format {
        Some("dependency-index/v2") => digest(document.payload.get().as_bytes()),
        None => {
            let payload: Value = serde_json::from_str(document.payload.get())?;
            digest(&serde_json::to_vec(&payload)?)
        }
        Some(_) => anyhow::bail!("unsupported dependency index envelope"),
    };
    ensure!(
        document.sha256 == actual,
        "dependency index checksum mismatch"
    );
    Ok(serde_json::from_str(document.payload.get())?)
}

pub(crate) fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // Hash the exact serialized payload. Large typed indexes and bounded pages
    // need no second complete JSON tree or cloned deserialization payload.
    let payload = serde_json::to_vec(value)?;
    let sha256 = digest(&payload);
    let parent = path.parent().context("dependency index has no parent")?;
    let temporary = parent.join(format!(".dependency-index-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        write!(
            file,
            "{{\"format\":\"dependency-index/v2\",\"sha256\":\"{sha256}\",\"payload\":"
        )?;
        file.write_all(&payload)?;
        file.write_all(b"}")?;
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

pub(super) struct Lock(File);
impl Lock {
    pub(super) fn acquire(path: &Path, cancelled: &std::sync::atomic::AtomicBool) -> Result<Self> {
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
    validate: fn(&Value) -> Result<()>,
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
        prepare_cancellable(&source, &flag, validate).map(|(_, report)| report)
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
