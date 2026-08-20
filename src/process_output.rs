use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const CAPTURE_SCHEMA_VERSION: u32 = 1;
const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CAPTURE_BYTES: u64 = 64 * 1024 * 1024;
const MISSING_EXIT_CODE: i32 = 44;
const INVALID_TYPE_EXIT_CODE: i32 = 45;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessOutputConfig {
    pub(crate) id: String,
    pub(crate) path: PathBuf,
    pub(crate) comparison: ProcessOutputComparison,
    #[serde(default)]
    pub(crate) observation: ProcessOutputObservation,
    #[serde(default = "default_max_bytes")]
    pub(crate) max_bytes: u64,
}

const fn default_max_bytes() -> u64 {
    DEFAULT_MAX_BYTES
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ProcessOutputComparison {
    RegularFileExists,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProcessOutputObservation {
    #[default]
    BeforeShutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessOutputCaptureSide {
    Source,
    Target,
}

impl ProcessOutputCaptureSide {
    fn data_file(self) -> &'static str {
        match self {
            Self::Source => "source.data",
            Self::Target => "target.data",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessOutputCaptureReport {
    pub schema_version: u32,
    pub side: ProcessOutputCaptureSide,
    pub output_root: PathBuf,
    pub outputs: usize,
    pub present: usize,
    pub missing: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessOutputManifest {
    schema_version: u32,
    id: String,
    side: ProcessOutputCaptureSide,
    path: PathBuf,
    comparison: ProcessOutputComparison,
    observation: ProcessOutputObservation,
    present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessOutputComparisonResult {
    pub(crate) id: String,
    pub(crate) path: PathBuf,
    pub(crate) passed: bool,
    pub(crate) classification: &'static str,
    pub(crate) source_present: bool,
    pub(crate) target_present: bool,
}

pub(crate) fn validate_configs(configs: &[ProcessOutputConfig]) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    let mut total_max_bytes = 0u64;
    for config in configs {
        validate_id(&config.id)?;
        ensure!(
            ids.insert(config.id.as_str()),
            "process output id {:?} is duplicated",
            config.id
        );
        validate_container_path(&config.path)?;
        ensure!(
            (1..=MAX_FILE_BYTES).contains(&config.max_bytes),
            "process output {} max_bytes must be between 1 and {MAX_FILE_BYTES}",
            config.id
        );
        total_max_bytes = total_max_bytes
            .checked_add(config.max_bytes)
            .context("process output max_bytes total overflowed")?;
    }
    ensure!(
        total_max_bytes <= MAX_CAPTURE_BYTES,
        "process output max_bytes total must not exceed {MAX_CAPTURE_BYTES}"
    );
    Ok(())
}

pub fn capture_project_process_outputs(
    target_root: &Path,
    container: &str,
    side: ProcessOutputCaptureSide,
    output_root: &Path,
) -> Result<ProcessOutputCaptureReport> {
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    capture_process_outputs(container, &project.process_outputs, side, output_root)
}

pub(crate) fn capture_process_outputs(
    container: &str,
    configs: &[ProcessOutputConfig],
    side: ProcessOutputCaptureSide,
    output_root: &Path,
) -> Result<ProcessOutputCaptureReport> {
    validate_configs(configs)?;
    validate_container_name(container)?;
    if configs.is_empty() {
        return Ok(ProcessOutputCaptureReport {
            schema_version: CAPTURE_SCHEMA_VERSION,
            side,
            output_root: output_root.to_path_buf(),
            outputs: 0,
            present: 0,
            missing: 0,
        });
    }
    ensure!(
        !output_root.exists(),
        "process output capture root already exists: {}",
        output_root.display()
    );
    let parent = output_root
        .parent()
        .context("process output capture root has no parent")?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create process output capture parent {}",
            parent.display()
        )
    })?;
    let staging = parent.join(format!(
        ".process-outputs-{}.staging",
        Uuid::new_v4().simple()
    ));
    fs::create_dir(&staging).with_context(|| {
        format!(
            "failed to create process output staging {}",
            staging.display()
        )
    })?;
    let result = capture_into_staging(container, configs, side, output_root, &staging);
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn capture_into_staging(
    container: &str,
    configs: &[ProcessOutputConfig],
    side: ProcessOutputCaptureSide,
    output_root: &Path,
    staging: &Path,
) -> Result<ProcessOutputCaptureReport> {
    let mut present = 0usize;
    for config in configs {
        let directory = staging.join(&config.id);
        fs::create_dir(&directory)?;
        let size = probe_regular_file(container, &config.path)?;
        let manifest = match size {
            None => ProcessOutputManifest {
                schema_version: CAPTURE_SCHEMA_VERSION,
                id: config.id.clone(),
                side,
                path: config.path.clone(),
                comparison: config.comparison,
                observation: config.observation,
                present: false,
                size_bytes: None,
                fingerprint: None,
            },
            Some(size) => {
                ensure!(
                    size <= config.max_bytes,
                    "process output {} is {size} bytes and exceeds max_bytes {}",
                    config.id,
                    config.max_bytes
                );
                let data = directory.join(side.data_file());
                copy_regular_file(container, &config.path, &data, size)?;
                present = present.saturating_add(1);
                ProcessOutputManifest {
                    schema_version: CAPTURE_SCHEMA_VERSION,
                    id: config.id.clone(),
                    side,
                    path: config.path.clone(),
                    comparison: config.comparison,
                    observation: config.observation,
                    present: true,
                    size_bytes: Some(size),
                    fingerprint: Some(file_fingerprint(&data)?),
                }
            }
        };
        write_json(&directory.join("manifest.json"), &manifest)?;
    }
    fs::rename(staging, output_root).with_context(|| {
        format!(
            "failed to publish process output capture {}",
            output_root.display()
        )
    })?;
    Ok(ProcessOutputCaptureReport {
        schema_version: CAPTURE_SCHEMA_VERSION,
        side,
        output_root: output_root.to_path_buf(),
        outputs: configs.len(),
        present,
        missing: configs.len().saturating_sub(present),
    })
}

pub(crate) fn validate_capture_set(
    configs: &[ProcessOutputConfig],
    side: ProcessOutputCaptureSide,
    root: &Path,
    require_present: bool,
) -> Result<()> {
    validate_configs(configs)?;
    if configs.is_empty() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("process output capture is missing: {}", root.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "process output capture root must be a directory and not a symlink"
    );
    for config in configs {
        let manifest = read_manifest(root, config, side)?;
        if require_present {
            ensure!(
                manifest.present,
                "source process output {} is missing",
                config.id
            );
        }
        validate_data(root, config, side, &manifest)?;
    }
    Ok(())
}

pub(crate) fn compare_capture(
    config: &ProcessOutputConfig,
    source_root: &Path,
    target_root: &Path,
) -> Result<ProcessOutputComparisonResult> {
    let source = read_manifest(source_root, config, ProcessOutputCaptureSide::Source)?;
    let target = read_manifest(target_root, config, ProcessOutputCaptureSide::Target)?;
    validate_data(
        source_root,
        config,
        ProcessOutputCaptureSide::Source,
        &source,
    )?;
    validate_data(
        target_root,
        config,
        ProcessOutputCaptureSide::Target,
        &target,
    )?;
    ensure!(
        source.present,
        "source process output {} is missing",
        config.id
    );
    let passed = match config.comparison {
        ProcessOutputComparison::RegularFileExists => target.present,
    };
    Ok(ProcessOutputComparisonResult {
        id: config.id.clone(),
        path: config.path.clone(),
        passed,
        classification: if passed { "equal" } else { "candidate_missing" },
        source_present: source.present,
        target_present: target.present,
    })
}

fn read_manifest(
    root: &Path,
    config: &ProcessOutputConfig,
    side: ProcessOutputCaptureSide,
) -> Result<ProcessOutputManifest> {
    let path = root.join(&config.id).join("manifest.json");
    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read process output manifest {}", path.display()))?;
    let manifest: ProcessOutputManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid process output manifest {}", path.display()))?;
    ensure!(
        manifest.schema_version == CAPTURE_SCHEMA_VERSION
            && manifest.id == config.id
            && manifest.side == side
            && manifest.path == config.path
            && manifest.comparison == config.comparison
            && manifest.observation == config.observation,
        "process output manifest does not match configured output {}",
        config.id
    );
    ensure!(
        manifest.present == manifest.size_bytes.is_some()
            && manifest.present == manifest.fingerprint.is_some(),
        "process output manifest presence fields are inconsistent for {}",
        config.id
    );
    Ok(manifest)
}

fn validate_data(
    root: &Path,
    config: &ProcessOutputConfig,
    side: ProcessOutputCaptureSide,
    manifest: &ProcessOutputManifest,
) -> Result<()> {
    let data = root.join(&config.id).join(side.data_file());
    if !manifest.present {
        ensure!(
            !data.exists(),
            "missing process output {} unexpectedly contains captured data",
            config.id
        );
        return Ok(());
    }
    let metadata = fs::symlink_metadata(&data).with_context(|| {
        format!(
            "captured process output data is missing: {}",
            data.display()
        )
    })?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "captured process output data must be a regular file and not a symlink"
    );
    ensure!(
        Some(metadata.len()) == manifest.size_bytes,
        "captured process output size does not match its manifest for {}",
        config.id
    );
    ensure!(
        manifest.fingerprint.as_deref() == Some(file_fingerprint(&data)?.as_str()),
        "captured process output fingerprint does not match its manifest for {}",
        config.id
    );
    Ok(())
}

fn probe_regular_file(container: &str, path: &Path) -> Result<Option<u64>> {
    let path = path
        .to_str()
        .context("process output path must be valid UTF-8")?;
    let output = Command::new("docker")
        .args([
            "exec",
            "--user",
            "0:0",
            container,
            "/bin/sh",
            "-c",
            "if [ ! -e \"$1\" ] && [ ! -L \"$1\" ]; then exit 44; fi; \
             if [ ! -f \"$1\" ] || [ -L \"$1\" ]; then exit 45; fi; \
             stat -c %s -- \"$1\"",
            "process-output-probe",
            path,
        ])
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to inspect process output {path}"))?;
    match output.status.code() {
        Some(0) => {
            let size = String::from_utf8(output.stdout)
                .context("process output size is not valid UTF-8")?
                .trim()
                .parse::<u64>()
                .context("process output size is invalid")?;
            Ok(Some(size))
        }
        Some(MISSING_EXIT_CODE) => Ok(None),
        Some(INVALID_TYPE_EXIT_CODE) => {
            bail!("process output {path} must be a regular file and not a symlink")
        }
        _ => bail!(
            "failed to inspect process output {path}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

fn copy_regular_file(container: &str, path: &Path, destination: &Path, size: u64) -> Result<()> {
    let source = format!("{container}:{}", path.display());
    let output = Command::new("docker")
        .args(["cp", "--archive", &source])
        .arg(destination)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to copy process output {}", path.display()))?;
    ensure!(
        output.status.success(),
        "failed to copy process output {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let metadata = fs::symlink_metadata(destination).with_context(|| {
        format!(
            "copied process output is missing: {}",
            destination.display()
        )
    })?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "copied process output must be a regular file and not a symlink"
    );
    ensure!(
        metadata.len() == size,
        "process output changed while it was being captured"
    );
    File::open(destination)?.sync_all()?;
    Ok(())
}

fn validate_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') }),
        "process output id must contain 1-64 ASCII letters, digits, '.', '_', or '-'"
    );
    Ok(())
}

fn validate_container_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path != Path::new("/"),
        "process output path must be an absolute file path"
    );
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "process output path must not contain relative components"
    );
    ensure!(
        path.to_str()
            .is_some_and(|value| !value.contains(['\r', '\n'])),
        "process output path must be valid single-line UTF-8"
    );
    Ok(())
}

fn validate_container_name(container: &str) -> Result<()> {
    ensure!(
        container == container.trim()
            && !container.is_empty()
            && !container.contains(['\r', '\n', ':']),
        "process output container name must be non-empty and single-line"
    );
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn file_fingerprint(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = 0xcbf29ce484222325u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        for byte in &buffer[..read] {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    Ok(format!("fnv1a64:{hash:016x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ProcessOutputConfig {
        ProcessOutputConfig {
            id: "metrics-profile".to_string(),
            path: PathBuf::from("/data1/weibo/logs/profile.log"),
            comparison: ProcessOutputComparison::RegularFileExists,
            observation: ProcessOutputObservation::BeforeShutdown,
            max_bytes: 1024,
        }
    }

    #[test]
    fn validates_bounded_process_output_configuration() {
        validate_configs(&[config()]).unwrap();
        let mut invalid = config();
        invalid.id = "metrics/profile".to_string();
        assert!(validate_configs(&[invalid]).is_err());
        let mut invalid = config();
        invalid.path = PathBuf::from("relative.log");
        assert!(validate_configs(&[invalid]).is_err());
    }

    #[test]
    fn regular_file_exists_compares_presence_but_keeps_data() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let target = root.path().join("target");
        write_capture(
            &source,
            ProcessOutputCaptureSide::Source,
            true,
            b"source bytes",
        );
        write_capture(
            &target,
            ProcessOutputCaptureSide::Target,
            true,
            b"different bytes",
        );

        let result = compare_capture(&config(), &source, &target).unwrap();

        assert!(result.passed);
        assert_eq!(result.classification, "equal");
        assert!(source.join("metrics-profile/source.data").is_file());
        assert!(target.join("metrics-profile/target.data").is_file());
    }

    #[test]
    fn regular_file_exists_reports_a_missing_target() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let target = root.path().join("target");
        write_capture(
            &source,
            ProcessOutputCaptureSide::Source,
            true,
            b"source bytes",
        );
        write_capture(&target, ProcessOutputCaptureSide::Target, false, b"");

        let result = compare_capture(&config(), &source, &target).unwrap();

        assert!(!result.passed);
        assert_eq!(result.classification, "candidate_missing");
    }

    fn write_capture(root: &Path, side: ProcessOutputCaptureSide, present: bool, bytes: &[u8]) {
        let directory = root.join("metrics-profile");
        fs::create_dir_all(&directory).unwrap();
        let (size_bytes, fingerprint) = if present {
            let data = directory.join(side.data_file());
            fs::write(&data, bytes).unwrap();
            (
                Some(bytes.len() as u64),
                Some(file_fingerprint(&data).unwrap()),
            )
        } else {
            (None, None)
        };
        write_json(
            &directory.join("manifest.json"),
            &ProcessOutputManifest {
                schema_version: CAPTURE_SCHEMA_VERSION,
                id: "metrics-profile".to_string(),
                side,
                path: PathBuf::from("/data1/weibo/logs/profile.log"),
                comparison: ProcessOutputComparison::RegularFileExists,
                observation: ProcessOutputObservation::BeforeShutdown,
                present,
                size_bytes,
                fingerprint,
            },
        )
        .unwrap();
    }
}
