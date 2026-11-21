//! Fixed-identity Source processes, CA trust and graceful process-group cleanup.

use crate::{ArtifactOwner, TRAFFIC_PROCESS_GID, TRAFFIC_PROCESS_UID};
use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;
use tokio::process::{Child, Command};
use tracing::warn;

const SOURCE_STOP_TIMEOUT: Duration = Duration::from_secs(15);
const JAVA_TRUSTSTORE_PASSWORD: &str = "changeit";

pub(super) struct RuntimeDirectory {
    pub(super) path: PathBuf,
}

impl RuntimeDirectory {
    pub(super) fn create(data_root: &Path) -> Result<Self> {
        let path = data_root
            .join("runtime")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn spawn_source(
    program: &Path,
    arguments: &[OsString],
    working_directory: &Path,
    trust_environment: &[(OsString, OsString)],
) -> Result<Child> {
    let mut command = fixed_identity_command()?;
    command
        .arg(program)
        .args(arguments)
        .current_dir(working_directory)
        .env_remove(crate::request_headers::ENCRYPTION_KEY_ENV)
        .envs(trust_environment.iter().cloned())
        .stdin(Stdio::inherit())
        .stdout(duplicate_stderr()?)
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    command.as_std_mut().process_group(0);
    command.spawn().with_context(|| {
        format!(
            "failed to start Source command as {}:{}: {}",
            TRAFFIC_PROCESS_UID,
            TRAFFIC_PROCESS_GID,
            program.display()
        )
    })
}

pub fn fixed_identity_command() -> Result<Command> {
    Ok(Command::from(fixed_identity_std_command()?))
}

pub fn fixed_identity_std_command() -> Result<StdCommand> {
    let setpriv = system_program("setpriv")?;
    let mut command = if unsafe { libc::geteuid() } == 0 {
        StdCommand::new(setpriv)
    } else {
        let mut command = StdCommand::new(system_program("sudo")?);
        command.args(["-n", "--"]).arg(setpriv);
        command
    };
    command.args([
        OsString::from("--reuid"),
        OsString::from(TRAFFIC_PROCESS_UID.to_string()),
        OsString::from("--regid"),
        OsString::from(TRAFFIC_PROCESS_GID.to_string()),
        OsString::from("--clear-groups"),
        OsString::from("--"),
    ]);
    Ok(command)
}

pub fn prepare_fixed_identity() -> Result<()> {
    system_program("setpriv").context("setpriv is required to launch Source as 998:998")?;
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    let sudo = system_program("sudo").context("sudo is required to launch Source as 998:998")?;
    let status = std::process::Command::new(sudo)
        .arg("-n")
        .arg(system_program("true")?)
        .status()
        .context("failed to check non-interactive sudo permission")?;
    ensure!(
        status.success(),
        "record requires root or non-interactive sudo permission"
    );
    Ok(())
}

pub fn verify_fixed_identity_access(working_directory: &Path, program: &Path) -> Result<()> {
    for (flag, path, label) in [
        ("-x", working_directory, "source working directory"),
        ("-x", program, "source executable"),
    ] {
        let status = fixed_identity_std_command()?
            .arg(system_program("test")?)
            .arg(flag)
            .arg(path)
            .status()
            .with_context(|| format!("failed to verify fixed-identity access to {label}"))?;
        ensure!(
            status.success(),
            "Source identity {}:{} cannot access {label}: {}",
            TRAFFIC_PROCESS_UID,
            TRAFFIC_PROCESS_GID,
            path.display()
        );
    }
    Ok(())
}

pub fn verify_fixed_identity_denied(flag: &str, path: &Path, label: &str) -> Result<()> {
    let status = fixed_identity_std_command()?
        .arg(system_program("test")?)
        .arg(flag)
        .arg(path)
        .status()
        .with_context(|| format!("failed to verify Source isolation from {label}"))?;
    ensure!(
        !status.success(),
        "Source identity {}:{} must not access {label}: {}",
        TRAFFIC_PROCESS_UID,
        TRAFFIC_PROCESS_GID,
        path.display()
    );
    Ok(())
}

pub fn prepare_source_trust(
    runtime_directory: &Path,
    recorder_ca: &Path,
    working_directory: &Path,
    source_program: &Path,
) -> Result<Vec<(OsString, OsString)>> {
    ensure!(
        recorder_ca.is_file(),
        "Recorder CA was not generated before Source startup: {}",
        recorder_ca.display()
    );
    let bundle = runtime_directory.join("source-ca-bundle.pem");
    write_ca_bundle(&bundle, recorder_ca, working_directory)?;
    verify_fixed_identity_read(&bundle, "generated Source CA bundle")?;

    let mut environment = [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
    ]
    .into_iter()
    .map(|name| (OsString::from(name), bundle.as_os_str().to_owned()))
    .collect::<Vec<_>>();
    environment.push((
        OsString::from("TRAFFIC_E2E_RECORDER_CA"),
        recorder_ca.as_os_str().to_owned(),
    ));

    if let Some(keytool) = find_on_path(OsStr::new("keytool")) {
        let truststore = runtime_directory.join("source-truststore.jks");
        let output = std::process::Command::new(keytool)
            .args(["-importcert", "-noprompt", "-alias", "traffic-recorder-ca"])
            .arg("-file")
            .arg(recorder_ca)
            .arg("-keystore")
            .arg(&truststore)
            .args(["-storetype", "JKS", "-storepass", JAVA_TRUSTSTORE_PASSWORD])
            .output()
            .context("failed to create Source Java truststore")?;
        ensure!(
            output.status.success(),
            "failed to create Source Java truststore: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        fs::set_permissions(&truststore, fs::Permissions::from_mode(0o644))?;
        verify_fixed_identity_read(&truststore, "generated Source Java truststore")?;
        let mut java_options = std::env::var_os("JAVA_TOOL_OPTIONS").unwrap_or_default();
        if !java_options.is_empty() {
            java_options.push(" ");
        }
        java_options.push(format!(
            "-Djavax.net.ssl.trustStore={} -Djavax.net.ssl.trustStorePassword={JAVA_TRUSTSTORE_PASSWORD}",
            truststore.display()
        ));
        environment.push((OsString::from("JAVA_TOOL_OPTIONS"), java_options));
    } else if source_program
        .file_name()
        .is_some_and(|name| name == OsStr::new("java"))
    {
        bail!("Java Source HTTPS recording requires keytool on PATH")
    }
    Ok(environment)
}

pub fn write_ca_bundle(bundle: &Path, recorder_ca: &Path, working_directory: &Path) -> Result<()> {
    let mut candidates = Vec::new();
    for name in [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
    ] {
        if let Some(value) = std::env::var_os(name) {
            let path = resolve_from(working_directory, Path::new(&value));
            ensure!(
                path.is_file(),
                "inherited {name} does not name a readable CA file: {}",
                path.display()
            );
            candidates.push(path);
        }
    }
    if candidates.is_empty() {
        candidates.extend(
            [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem",
            ]
            .into_iter()
            .map(PathBuf::from)
            .filter(|path| path.is_file())
            .take(1),
        );
    }
    candidates.push(recorder_ca.to_path_buf());

    let mut unique = BTreeSet::new();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(bundle)
        .with_context(|| format!("failed to create Source CA bundle {}", bundle.display()))?;
    for candidate in candidates {
        let candidate = candidate.canonicalize().with_context(|| {
            format!("failed to resolve Source CA input {}", candidate.display())
        })?;
        if !unique.insert(candidate.clone()) {
            continue;
        }
        let bytes = fs::read(&candidate)
            .with_context(|| format!("failed to read Source CA input {}", candidate.display()))?;
        file.write_all(&bytes)?;
        if !bytes.ends_with(b"\n") {
            file.write_all(b"\n")?;
        }
    }
    file.sync_all()?;
    Ok(())
}

pub fn verify_fixed_identity_read(path: &Path, label: &str) -> Result<()> {
    let status = fixed_identity_std_command()?
        .arg(system_program("test")?)
        .arg("-r")
        .arg(path)
        .status()
        .with_context(|| format!("failed to verify fixed-identity access to {label}"))?;
    ensure!(
        status.success(),
        "Source identity {}:{} cannot read {label}: {}",
        TRAFFIC_PROCESS_UID,
        TRAFFIC_PROCESS_GID,
        path.display()
    );
    Ok(())
}

pub async fn stop_source(source: &mut Child) -> Result<()> {
    if source
        .try_wait()
        .context("failed to inspect Source")?
        .is_some()
    {
        return Ok(());
    }
    signal_process_group(source, libc::SIGTERM).context("failed to stop Source")?;
    if let Ok(status) = tokio::time::timeout(SOURCE_STOP_TIMEOUT, source.wait()).await {
        status.context("failed to wait for Source after SIGTERM")?;
        return Ok(());
    }
    warn!("Source did not stop after SIGTERM; sending SIGKILL");
    let _ = signal_process_group(source, libc::SIGKILL);
    let _ = source.kill().await;
    source
        .wait()
        .await
        .context("failed to reap Source after SIGKILL")?;
    Ok(())
}

pub fn signal_process_group(child: &Child, signal: libc::c_int) -> Result<()> {
    let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) else {
        return Ok(());
    };
    let result = unsafe { libc::kill(-pid, signal) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(error.into())
}

pub fn duplicate_stderr() -> Result<Stdio> {
    let fd = unsafe { libc::dup(libc::STDERR_FILENO) };
    ensure!(
        fd >= 0,
        "failed to duplicate stderr: {}",
        std::io::Error::last_os_error()
    );
    let file = unsafe { fs::File::from_raw_fd(fd) };
    Ok(Stdio::from(file))
}

pub fn resolve_source_program(value: &OsStr, working_directory: &Path) -> Result<PathBuf> {
    let value_path = Path::new(value);
    let path = if value_path.components().count() > 1 {
        resolve_from(working_directory, value_path)
    } else {
        find_on_path(value).context("source command was not found on PATH")?
    };
    let path = path
        .canonicalize()
        .with_context(|| format!("source command does not exist: {}", path.display()))?;
    let metadata = fs::metadata(&path)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "source command is not executable: {}",
        path.display()
    );
    Ok(path)
}

pub fn find_on_path(command: &OsStr) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(command))
            .find(|candidate| {
                fs::metadata(candidate).is_ok_and(|metadata| {
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                })
            })
    })
}

pub fn system_program(name: &str) -> Result<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .into_iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|path| path.is_file())
        .with_context(|| format!("required system command not found: {name}"))
}

pub fn prepare_recordings_root(target_root: &Path, owner: ArtifactOwner) -> Result<PathBuf> {
    let recordings_root = target_root
        .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
        .join("recordings");
    fs::create_dir_all(&recordings_root).with_context(|| {
        format!(
            "failed to create canonical recordings root {}",
            recordings_root.display()
        )
    })?;
    let metadata = fs::symlink_metadata(&recordings_root)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "canonical recordings root must be a directory and not a symlink: {}",
        recordings_root.display()
    );
    fs::set_permissions(&recordings_root, fs::Permissions::from_mode(0o700)).with_context(
        || {
            format!(
                "failed to protect canonical recordings root {}",
                recordings_root.display()
            )
        },
    )?;
    if unsafe { libc::geteuid() } == 0 {
        owner.assign_path_to(&recordings_root)?;
    }
    verify_fixed_identity_denied("-x", &recordings_root, "recording artifacts")?;
    Ok(recordings_root)
}

pub fn verify_sensitive_state_isolated(
    target_root: &Path,
    recordings_root: &Path,
    recorder_ca_key: &Path,
) -> Result<()> {
    let encryption_key = target_root.join(crate::repository::LOCAL_ENCRYPTION_KEY_PATH);
    for (path, label) in [
        (encryption_key.as_path(), "request-header encryption key"),
        (recorder_ca_key, "Recorder CA private key"),
    ] {
        ensure!(
            path.is_file(),
            "{label} was not initialized before Source startup: {}",
            path.display()
        );
        verify_fixed_identity_denied("-r", path, label)?;
    }
    verify_fixed_identity_denied("-x", recordings_root, "recording artifacts")
}

fn resolve_from(base: &Path, path: &Path) -> PathBuf {
    normalize_path(if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    })
}

fn normalize_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::Normal(value) => normalized.push(value),
        }
    }
    normalized
}
