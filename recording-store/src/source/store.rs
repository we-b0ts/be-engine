//! Authenticated cache envelopes, private publication and bounded lock waits.
use super::{FileStamp, digest};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

pub fn cache_directory(root: &Path) -> PathBuf {
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

pub fn file_cache_directory(path: &Path, source: &super::scoped::Source) -> Result<PathBuf> {
    let Some(scope) = source.scope_sha256()? else {
        return Ok(cache_directory(path));
    };
    // Each attempt publishes its own immutable view. Identical views over the
    // same ledger select the same records even when their paths and inodes differ.
    Ok(cache_directory(&source.path).join(format!("scope-file-v1-{scope}")))
}

pub fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path)?;
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "refusing linked dependency index directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    FileStamp::read(path)?;
    decode_json(&fs::read(path)?).map(|(value, _)| value)
}

pub fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<(T, String)> {
    #[derive(serde::Deserialize)]
    struct Document<'a> {
        #[serde(default)]
        format: Option<&'a str>,
        sha256: &'a str,
        #[serde(borrow)]
        payload: &'a serde_json::value::RawValue,
    }
    let document: Document<'_> = serde_json::from_slice(bytes)?;
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
    Ok((serde_json::from_str(document.payload.get())?, actual))
}

pub fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
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

pub struct Lock(File);
impl Lock {
    pub fn acquire(path: &Path, cancelled: &std::sync::atomic::AtomicBool) -> Result<Self> {
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

pub fn check_cancelled(cancelled: &std::sync::atomic::AtomicBool) -> Result<()> {
    ensure!(
        !cancelled.load(std::sync::atomic::Ordering::Relaxed),
        "dependency index preparation cancelled"
    );
    Ok(())
}
