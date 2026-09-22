use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::num::{NonZeroU64, NonZeroUsize};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::io::FromRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command as StdCommand, ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::process::{Child, Command};
use tracing::{info, warn};

use crate::recording_control::{
    RecordingWaitConfig, wait_for_recording_listeners, wait_for_recording_ready,
};
use crate::{AppConfig, ArtifactOwner, RecordingApi, TRAFFIC_PROCESS_GID, TRAFFIC_PROCESS_UID};

const SOURCE_STOP_TIMEOUT: Duration = Duration::from_secs(15);
const RECORDER_STOP_TIMEOUT: Duration = Duration::from_secs(180);
const JAVA_TRUSTSTORE_PASSWORD: &str = "changeit";

#[derive(Debug, Clone)]
pub struct SourceRecordingOptions {
    pub target_root: PathBuf,
    pub run_id: Option<String>,
    pub duration_seconds: NonZeroU64,
    pub startup_timeout_seconds: NonZeroU64,
    pub apis: Vec<RecordingApi>,
    pub per_api_case_limit: Option<NonZeroUsize>,
    pub source_working_directory: Option<PathBuf>,
    pub source_command: Vec<OsString>,
}

#[derive(Debug, Serialize)]
pub struct SourceRecordingResult {
    pub status: &'static str,
    pub run_id: String,
    pub target_root: PathBuf,
    pub manifest: PathBuf,
    pub recorder_ca: PathBuf,
    pub source_uid: u32,
    pub source_gid: u32,
    pub managed_by: &'static str,
}

#[derive(Debug)]
enum SessionEnd {
    RecorderExited(ExitStatus),
    DurationElapsed,
    SourceExited(ExitStatus),
    Interrupted,
}

#[derive(Debug, Deserialize)]
struct RecordingManifest {
    status: String,
    failed_cases: usize,
    errors: Vec<Value>,
}

struct RuntimeDirectory {
    path: PathBuf,
}

impl RuntimeDirectory {
    fn create(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create record-source runtime parent {}",
                    parent.display()
                )
            })?;
        }
        fs::create_dir(&path).with_context(|| {
            format!(
                "record-source runtime already exists or cannot be created: {}",
                path.display()
            )
        })?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        Ok(Self { path })
    }
}

impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(
                path = %self.path.display(),
                error = %error,
                "failed to remove record-source runtime directory"
            );
        }
    }
}

pub async fn run_source_recording(
    options: SourceRecordingOptions,
) -> Result<SourceRecordingResult> {
    ensure!(
        !options.source_command.is_empty(),
        "record-source requires a source command after --"
    );
    let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    let recorder_config = AppConfig::load(&project.recorder_config)?;
    validate_artifact_root(&target_root, &recorder_config)?;

    let run_id = options
        .run_id
        .clone()
        .unwrap_or_else(|| Utc::now().format("%Y%m%d%H%M%S").to_string());
    validate_run_id(&run_id)?;
    let recording_dir = target_root
        .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
        .join("recordings")
        .join(&run_id);
    ensure!(
        !recording_dir.exists(),
        "recording run already exists: {}",
        recording_dir.display()
    );
    let manifest = recording_dir.join("recording-run.json");
    let source_working_directory =
        resolve_working_directory(&target_root, options.source_working_directory.as_deref())?;
    let source_program =
        resolve_source_program(&options.source_command[0], &source_working_directory)?;

    prepare_fixed_identity()?;
    let controller_owner = ArtifactOwner::invoking()?;
    ensure!(
        controller_owner.uid() != TRAFFIC_PROCESS_UID,
        "record-source controller owner must not use reserved Source UID {TRAFFIC_PROCESS_UID}"
    );
    verify_fixed_identity_access(&source_working_directory, &source_program)?;
    let recordings_root = prepare_recordings_root(&target_root, controller_owner)?;

    let runtime = RuntimeDirectory::create(
        target_root
            .join(crate::repository::LOCAL_ROOT)
            .join("runtime/record-source")
            .join(&run_id),
    )?;
    let control_socket = runtime.path.join("recorder.sock");
    let encryption_key = crate::platform::encryption_key::load_or_create(&target_root)?;
    let recorder_ca = resolve_target_path(&target_root, &recorder_config.tls.ca_cert_path);
    let recorder_ca_key = resolve_target_path(&target_root, &recorder_config.tls.ca_key_path);

    let mut recorder = spawn_recorder(
        &target_root,
        &project.recorder_config,
        &control_socket,
        &run_id,
        &options,
        &encryption_key,
    )?;
    let mut source = None;
    let session_result = async {
        if let Some(end) = wait_for_listeners_or_end(
            &mut recorder,
            &control_socket,
            options.startup_timeout_seconds,
        )
        .await?
        {
            return Ok(end);
        }

        verify_sensitive_state_isolated(&target_root, &recordings_root, &recorder_ca_key)?;
        let trust_environment = prepare_source_trust(
            &runtime.path,
            &recorder_ca,
            &source_working_directory,
            &source_program,
        )?;
        source = Some(spawn_source(
            &source_program,
            &options.source_command[1..],
            &source_working_directory,
            &trust_environment,
        )?);
        let source_child = source.as_mut().expect("source was just started");

        if let Some(end) = wait_for_ready_or_end(
            &mut recorder,
            source_child,
            &control_socket,
            options.startup_timeout_seconds,
        )
        .await?
        {
            return Ok(end);
        }

        info!(
            run_id,
            duration_seconds = options.duration_seconds.get(),
            "record-source source is ready; recording window started"
        );
        monitor_recording_window(
            &mut recorder,
            source_child,
            Duration::from_secs(options.duration_seconds.get()),
        )
        .await
    }
    .await;

    // Keep Source available while Recorder drains active cases and publishes
    // the immutable manifest. Source is always stopped afterwards.
    let recorder_stop = stop_recorder(&mut recorder).await;
    let source_stop = match source.as_mut() {
        Some(source) => stop_source(source).await,
        None => Ok(()),
    };

    let session_end = match session_result {
        Ok(end) => end,
        Err(error) => {
            if let Err(cleanup) = recorder_stop {
                return Err(error.context(format!("Recorder cleanup also failed: {cleanup:#}")));
            }
            if let Err(cleanup) = source_stop {
                return Err(error.context(format!("Source cleanup also failed: {cleanup:#}")));
            }
            return Err(error);
        }
    };
    let stopped_recorder_status = recorder_stop?;
    source_stop?;
    let recorder_status = match session_end {
        SessionEnd::RecorderExited(status) => status,
        _ => stopped_recorder_status,
    };
    ensure!(
        recorder_status.success(),
        "Recorder exited with {recorder_status}"
    );

    match session_end {
        SessionEnd::SourceExited(status) => {
            bail!("source exited before recording completed: {status}")
        }
        SessionEnd::Interrupted => bail!("record-source was interrupted"),
        SessionEnd::RecorderExited(_) | SessionEnd::DurationElapsed => {}
    }

    validate_manifest(&manifest)?;
    Ok(SourceRecordingResult {
        status: "completed",
        run_id,
        target_root,
        manifest,
        recorder_ca,
        source_uid: TRAFFIC_PROCESS_UID,
        source_gid: TRAFFIC_PROCESS_GID,
        managed_by: "traffic-e2e",
    })
}

async fn wait_for_listeners_or_end(
    recorder: &mut Child,
    control_socket: &Path,
    timeout_seconds: NonZeroU64,
) -> Result<Option<SessionEnd>> {
    let wait = wait_for_recording_listeners(RecordingWaitConfig {
        control_socket_path: control_socket.to_path_buf(),
        timeout: Duration::from_secs(timeout_seconds.get()),
    });
    tokio::pin!(wait);
    tokio::select! {
        readiness = &mut wait => {
            readiness?;
            Ok(None)
        }
        status = recorder.wait() => Ok(Some(SessionEnd::RecorderExited(
            status.context("failed to wait for Recorder startup")?
        ))),
        signal = shutdown_signal() => {
            signal?;
            Ok(Some(SessionEnd::Interrupted))
        }
    }
}

async fn wait_for_ready_or_end(
    recorder: &mut Child,
    source: &mut Child,
    control_socket: &Path,
    timeout_seconds: NonZeroU64,
) -> Result<Option<SessionEnd>> {
    let wait = wait_for_recording_ready(RecordingWaitConfig {
        control_socket_path: control_socket.to_path_buf(),
        timeout: Duration::from_secs(timeout_seconds.get()),
    });
    tokio::pin!(wait);
    tokio::select! {
        readiness = &mut wait => {
            readiness?;
            Ok(None)
        }
        status = recorder.wait() => Ok(Some(SessionEnd::RecorderExited(
            status.context("failed to wait for Recorder readiness")?
        ))),
        status = source.wait() => Ok(Some(SessionEnd::SourceExited(
            status.context("failed to wait for Source startup")?
        ))),
        signal = shutdown_signal() => {
            signal?;
            Ok(Some(SessionEnd::Interrupted))
        }
    }
}

async fn monitor_recording_window(
    recorder: &mut Child,
    source: &mut Child,
    duration: Duration,
) -> Result<SessionEnd> {
    tokio::select! {
        _ = tokio::time::sleep(duration) => Ok(SessionEnd::DurationElapsed),
        status = recorder.wait() => Ok(SessionEnd::RecorderExited(
            status.context("failed to wait for Recorder")?
        )),
        status = source.wait() => Ok(SessionEnd::SourceExited(
            status.context("failed to wait for Source")?
        )),
        signal = shutdown_signal() => {
            signal?;
            Ok(SessionEnd::Interrupted)
        }
    }
}

fn spawn_recorder(
    target_root: &Path,
    recorder_config: &Path,
    control_socket: &Path,
    run_id: &str,
    options: &SourceRecordingOptions,
    encryption_key: &str,
) -> Result<Child> {
    let executable = crate::engine_binary::executable()?;
    let mut command = Command::new(executable);
    command
        .args(["internal", "recorder-run", "--config"])
        .arg(recorder_config)
        .arg("--control-socket")
        .arg(control_socket)
        .arg("--run-id")
        .arg(run_id)
        .arg("--dns")
        .current_dir(target_root)
        .env(crate::request_headers::ENCRYPTION_KEY_ENV, encryption_key)
        .stdin(Stdio::null())
        .stdout(duplicate_stderr()?)
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    if unsafe { libc::geteuid() } == 0 {
        command
            .arg("--artifact-owner")
            .arg(ArtifactOwner::invoking()?.to_string());
    }
    for api in &options.apis {
        command.arg("--api").arg(api.to_string());
    }
    if let Some(limit) = options.per_api_case_limit {
        command.arg("--per-api-case-limit").arg(limit.to_string());
    }
    command.as_std_mut().process_group(0);
    command.spawn().context("failed to start Recorder")
}

fn spawn_source(
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

fn fixed_identity_command() -> Result<Command> {
    Ok(Command::from(fixed_identity_std_command()?))
}

fn fixed_identity_std_command() -> Result<StdCommand> {
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

fn prepare_fixed_identity() -> Result<()> {
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
        "record-source requires root or non-interactive sudo permission"
    );
    Ok(())
}

fn verify_fixed_identity_access(working_directory: &Path, program: &Path) -> Result<()> {
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

fn prepare_recordings_root(target_root: &Path, owner: ArtifactOwner) -> Result<PathBuf> {
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

fn verify_sensitive_state_isolated(
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

fn verify_fixed_identity_denied(flag: &str, path: &Path, label: &str) -> Result<()> {
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

fn prepare_source_trust(
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

fn write_ca_bundle(bundle: &Path, recorder_ca: &Path, working_directory: &Path) -> Result<()> {
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

fn verify_fixed_identity_read(path: &Path, label: &str) -> Result<()> {
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

async fn stop_recorder(recorder: &mut Child) -> Result<ExitStatus> {
    if let Some(status) = recorder.try_wait().context("failed to inspect Recorder")? {
        return Ok(status);
    }
    signal_process_group(recorder, libc::SIGTERM).context("failed to stop Recorder")?;
    match tokio::time::timeout(RECORDER_STOP_TIMEOUT, recorder.wait()).await {
        Ok(status) => status.context("failed to wait for Recorder finalization"),
        Err(_) => {
            let _ = signal_process_group(recorder, libc::SIGKILL);
            let _ = recorder.kill().await;
            bail!("Recorder did not finalize within 180 seconds")
        }
    }
}

async fn stop_source(source: &mut Child) -> Result<()> {
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

fn signal_process_group(child: &Child, signal: libc::c_int) -> Result<()> {
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

fn duplicate_stderr() -> Result<Stdio> {
    let fd = unsafe { libc::dup(libc::STDERR_FILENO) };
    ensure!(
        fd >= 0,
        "failed to duplicate stderr: {}",
        std::io::Error::last_os_error()
    );
    let file = unsafe { fs::File::from_raw_fd(fd) };
    Ok(Stdio::from(file))
}

fn validate_artifact_root(target_root: &Path, config: &AppConfig) -> Result<()> {
    ensure!(
        config.artifacts.is_some(),
        "record-source requires recorder.artifacts.root_dir; legacy recording.output_dir is not supported"
    );
    let configured = resolve_target_path(target_root, &config.recording_output_dir());
    let expected = target_root
        .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
        .join("recordings");
    ensure!(
        configured == expected,
        "record-source requires recorder.artifacts.root_dir to resolve to {}; configured recording output resolves to {}",
        expected.display(),
        configured.display()
    );
    Ok(())
}

fn validate_run_id(run_id: &str) -> Result<()> {
    ensure!(
        run_id.len() == 14
            && run_id.bytes().all(|byte| byte.is_ascii_digit())
            && chrono::NaiveDateTime::parse_from_str(run_id, "%Y%m%d%H%M%S").is_ok(),
        "run ID must contain exactly 14 ASCII digits (YYYYMMDDHHMMSS)"
    );
    Ok(())
}

fn validate_manifest(path: &Path) -> Result<()> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "finalized recording manifest is missing: {}",
            path.display()
        )
    })?;
    let manifest: RecordingManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid recording manifest {}", path.display()))?;
    ensure!(
        manifest.status == "completed",
        "recording manifest status is {:?}, expected completed",
        manifest.status
    );
    ensure!(
        manifest.failed_cases == 0,
        "recording finalized with {} failed cases",
        manifest.failed_cases
    );
    ensure!(
        manifest.errors.is_empty(),
        "recording finalized with {} errors",
        manifest.errors.len()
    );
    Ok(())
}

fn resolve_working_directory(target_root: &Path, configured: Option<&Path>) -> Result<PathBuf> {
    let configured = configured.unwrap_or(Path::new("."));
    let directory = resolve_target_path(target_root, configured);
    if !configured.is_absolute() {
        ensure!(
            directory.starts_with(target_root),
            "relative source working directory must remain under target-root: {}",
            configured.display()
        );
    }
    ensure!(
        directory.is_dir(),
        "source working directory does not exist: {}",
        directory.display()
    );
    Ok(directory)
}

fn resolve_source_program(value: &OsStr, working_directory: &Path) -> Result<PathBuf> {
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

fn find_on_path(command: &OsStr) -> Option<PathBuf> {
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

fn system_program(name: &str) -> Result<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .into_iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|path| path.is_file())
        .with_context(|| format!("required system command not found: {name}"))
}

fn resolve_target_path(target_root: &Path, path: &Path) -> PathBuf {
    normalize_path(if path.is_absolute() {
        path.to_path_buf()
    } else {
        target_root.join(path)
    })
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

async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {}
        _ = hangup.recv() => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_artifact_contract_rejects_legacy_and_custom_outputs() {
        let root = Path::new("/target");
        let mut config = AppConfig {
            artifacts: Some(crate::ArtifactsConfig {
                root_dir: PathBuf::from("./.traffic-e2e/local/artifacts"),
            }),
            ..AppConfig::default()
        };
        assert!(validate_artifact_root(root, &config).is_ok());

        config.artifacts = None;
        assert!(validate_artifact_root(root, &config).is_err());
        config.artifacts = Some(crate::ArtifactsConfig {
            root_dir: PathBuf::from("./custom-artifacts"),
        });
        assert!(validate_artifact_root(root, &config).is_err());
    }

    #[test]
    fn run_id_requires_a_real_utc_timestamp_shape() {
        assert!(validate_run_id("20260922123045").is_ok());
        assert!(validate_run_id("20260230123045").is_err());
        assert!(validate_run_id("run-1").is_err());
    }

    #[test]
    fn finalized_manifest_must_be_clean() {
        let temporary = tempfile::tempdir().unwrap();
        let manifest = temporary.path().join("recording-run.json");
        fs::write(
            &manifest,
            r#"{"status":"completed","failed_cases":0,"errors":[]}"#,
        )
        .unwrap();
        assert!(validate_manifest(&manifest).is_ok());

        fs::write(
            &manifest,
            r#"{"status":"completed","failed_cases":1,"errors":[]}"#,
        )
        .unwrap();
        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn target_relative_paths_are_normalized_without_using_process_cwd() {
        assert_eq!(
            resolve_target_path(
                Path::new("/target"),
                Path::new("./.traffic-e2e/local/../local/artifacts")
            ),
            PathBuf::from("/target/.traffic-e2e/local/artifacts")
        );
    }

    #[test]
    fn relative_source_working_directory_cannot_escape_target_root() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        fs::create_dir(&target).unwrap();

        assert!(resolve_working_directory(&target, Some(Path::new("."))).is_ok());
        assert!(resolve_working_directory(&target, Some(Path::new(".."))).is_err());
    }
}
