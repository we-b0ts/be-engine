use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use tokio::process::{Child, Command};
use traffic_e2e::{TRAFFIC_PROCESS_GID, TRAFFIC_PROCESS_UID};
use uuid::Uuid;

use super::interception::{FIXED_USER, effective_uid, system_program, temp_root};
use super::signal::shutdown_signal;

mod environment;

use environment::{
    Assignment, assignment_argument, load_files, parse_assignment, validate_unique_assignments,
};

#[derive(Debug, Args)]
pub(super) struct TargetArgs {
    #[command(subcommand)]
    command: TargetCommand,
}

#[derive(Debug, Subcommand)]
enum TargetCommand {
    /// Stage and execute a prebuilt command as the fixed interception user.
    Exec(TargetExecArgs),
}

#[derive(Debug, Args)]
struct TargetExecArgs {
    /// Load dotenv values; later files and same-named caller values take precedence.
    #[arg(long = "env-file", value_name = "PATH")]
    env_files: Vec<PathBuf>,
    /// Copy one read-only file or directory and set NAME to its staged path.
    #[arg(long = "copy-env", value_name = "NAME=PATH", value_parser = parse_assignment)]
    copy_env: Vec<Assignment>,
    /// Set NAME to an existing path after checking fixed-user access.
    #[arg(long = "path-env", value_name = "NAME=PATH", value_parser = parse_assignment)]
    path_env: Vec<Assignment>,
    /// Set one non-reserved target environment value.
    #[arg(long = "env", value_name = "NAME=VALUE", value_parser = parse_assignment)]
    environment: Vec<Assignment>,
    /// Create a writable directory below the private target working directory.
    #[arg(long = "write-dir", value_name = "RELATIVE_PATH")]
    write_dirs: Vec<PathBuf>,
    /// Prebuilt target command and arguments.
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

struct Stage {
    root: PathBuf,
    work: PathBuf,
    inputs: PathBuf,
    binary: PathBuf,
}

impl Stage {
    fn create() -> Result<Self> {
        let temp = temp_root();
        ensure!(
            temp.is_dir(),
            "temporary directory does not exist: {}",
            temp.display()
        );
        let root = temp.join(format!("traffic-e2e-target.{}", Uuid::new_v4().simple()));
        fs::create_dir(&root)
            .with_context(|| format!("failed to create target stage {}", root.display()))?;
        let work = root.join("work");
        let inputs = root.join("inputs");
        let binary_dir = root.join("bin");
        let binary = binary_dir.join("target");
        fs::create_dir(&work)?;
        fs::create_dir(&inputs)?;
        fs::create_dir(&binary_dir)?;
        fs::create_dir(work.join("home"))?;
        fs::create_dir(work.join("tmp"))?;
        set_mode(&root, 0o750)?;
        set_mode(&inputs, 0o750)?;
        set_mode(&binary_dir, 0o750)?;
        set_mode(&work, 0o770)?;
        set_mode(&work.join("home"), 0o770)?;
        set_mode(&work.join("tmp"), 0o770)?;
        Ok(Self {
            root,
            work,
            inputs,
            binary,
        })
    }

    fn stage_command(&self, source: &Path) -> Result<()> {
        fs::copy(source, &self.binary).with_context(|| {
            format!(
                "failed to stage target command {} as {}",
                source.display(),
                self.binary.display()
            )
        })?;
        set_mode(&self.binary, 0o550)
    }

    fn create_write_dirs(&self, directories: &[PathBuf]) -> Result<()> {
        for relative in directories {
            validate_relative(relative)?;
            let destination = self.work.join(relative);
            fs::create_dir_all(&destination).with_context(|| {
                format!(
                    "failed to create target write directory {}",
                    destination.display()
                )
            })?;
            set_tree_mode(&destination, 0o770, 0o660)?;
        }
        Ok(())
    }

    fn copy_input(&self, index: usize, source: &Path) -> Result<PathBuf> {
        let destination = self.inputs.join(index.to_string());
        copy_read_only(source, &destination)?;
        Ok(destination)
    }

    fn assign_group(&self, gid: u32) -> Result<()> {
        root_command(
            "chgrp",
            [
                OsString::from("-R"),
                OsString::from(gid.to_string()),
                self.root.as_os_str().to_owned(),
            ],
        )
    }

    fn cleanup(&self) {
        if let Err(error) = root_command(
            "rm",
            [
                OsString::from("-rf"),
                OsString::from("--"),
                self.root.as_os_str().to_owned(),
            ],
        ) {
            eprintln!(
                "failed to remove target stage {}: {error:#}",
                self.root.display()
            );
        }
    }
}

pub(super) async fn run(args: TargetArgs) -> Result<()> {
    match args.command {
        TargetCommand::Exec(args) => run_exec(args).await,
    }
}

async fn run_exec(args: TargetExecArgs) -> Result<()> {
    validate_unique_assignments(
        args.copy_env
            .iter()
            .chain(&args.path_env)
            .chain(&args.environment),
    )?;
    prepare_privilege()?;
    verify_target_identity()?;

    let command = resolve_command(&args.command[0])?;
    let stage = Stage::create()?;
    let result = run_staged_target(&args, &command, &stage).await;
    stage.cleanup();
    result
}

async fn run_staged_target(args: &TargetExecArgs, command: &Path, stage: &Stage) -> Result<()> {
    stage.stage_command(command)?;
    stage.create_write_dirs(&args.write_dirs)?;
    let mut environment = load_files(&args.env_files)?;
    for (index, assignment) in args.copy_env.iter().enumerate() {
        let source_input = Path::new(&assignment.value);
        ensure!(
            !fs::symlink_metadata(source_input)
                .with_context(|| {
                    format!(
                        "--copy-env source does not exist: {}",
                        source_input.display()
                    )
                })?
                .file_type()
                .is_symlink(),
            "--copy-env does not accept symbolic links: {}",
            source_input.display()
        );
        let source = canonical_existing(source_input)?;
        let destination = stage.copy_input(index + 1, &source)?;
        environment.insert(assignment.name.clone(), destination.as_os_str().to_owned());
    }
    for assignment in &args.path_env {
        let source = canonical_existing(Path::new(&assignment.value))?;
        ensure_target_can_read(&source)?;
        environment.insert(assignment.name.clone(), source.into_os_string());
    }
    for assignment in &args.environment {
        environment.insert(assignment.name.clone(), assignment.value.clone());
    }
    stage.assign_group(TRAFFIC_PROCESS_GID)?;

    eprintln!(
        "replay target identity: user={FIXED_USER} uid={TRAFFIC_PROCESS_UID} \
         gid={TRAFFIC_PROCESS_GID}"
    );
    let mut child = spawn_target(args, stage, &environment)?;
    let status = tokio::select! {
        status = child.wait() => status?,
        signal = shutdown_signal() => {
            signal?;
            terminate_target(&mut child).await;
            child.wait().await?
        }
    };
    ensure!(status.success(), "target command exited with {status}");
    Ok(())
}

fn spawn_target(
    args: &TargetExecArgs,
    stage: &Stage,
    environment: &BTreeMap<String, OsString>,
) -> Result<Child> {
    let mut command = target_command()?;
    command
        .arg(system_program("env")?)
        .arg("-i")
        .arg(format!("HOME={}", stage.work.join("home").display()))
        .arg(format!("USER={FIXED_USER}"))
        .arg(format!("LOGNAME={FIXED_USER}"))
        .arg(format!("TMPDIR={}", stage.work.join("tmp").display()))
        .arg("PATH=/usr/local/bin:/usr/bin:/bin");
    for (name, value) in environment {
        command.arg(assignment_argument(name, value));
    }
    command
        .arg(&stage.binary)
        .args(&args.command[1..])
        .current_dir(&stage.work)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    command.spawn().context("failed to start fixed-user target")
}

fn target_command() -> Result<Command> {
    Ok(Command::from(target_std_command()?))
}

fn target_std_command() -> Result<StdCommand> {
    let setpriv = system_program("setpriv")?;
    let mut command = if effective_uid() == 0 {
        StdCommand::new(setpriv)
    } else {
        let mut command = StdCommand::new(system_program("sudo")?);
        command.args(["-n", "--"]).arg(setpriv);
        command
    };
    command.args(target_identity_args());
    Ok(command)
}

fn target_identity_args() -> [OsString; 6] {
    [
        OsString::from("--reuid"),
        OsString::from(TRAFFIC_PROCESS_UID.to_string()),
        OsString::from("--regid"),
        OsString::from(TRAFFIC_PROCESS_GID.to_string()),
        OsString::from("--clear-groups"),
        OsString::from("--"),
    ]
}

fn prepare_privilege() -> Result<()> {
    system_program("setpriv").context("setpriv is required to apply the fixed numeric identity")?;
    if effective_uid() == 0 {
        return Ok(());
    }
    let sudo = system_program("sudo").context("sudo is required")?;
    ensure!(
        StdCommand::new(&sudo)
            .args(["-n"])
            .arg(system_program("true")?)
            .status()
            .context("failed to check sudo permission")?
            .success(),
        "the caller needs non-interactive sudo permission"
    );
    Ok(())
}

fn verify_target_identity() -> Result<()> {
    verify_target_identity_field("-u", TRAFFIC_PROCESS_UID, "UID")?;
    verify_target_identity_field("-g", TRAFFIC_PROCESS_GID, "GID")
}

fn verify_target_identity_field(flag: &str, expected: u32, field: &str) -> Result<()> {
    let id = system_program("id")?;
    let output = target_std_command()?
        .arg(&id)
        .arg(flag)
        .output()
        .context("failed to verify fixed numeric target identity")?;
    ensure!(
        output.status.success(),
        "failed to verify fixed numeric target identity: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let actual = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .with_context(|| format!("fixed identity command returned a non-numeric {field}"))?;
    ensure!(
        actual == expected,
        "effective {field} {actual} does not match fixed traffic identity {expected}"
    );
    Ok(())
}

fn ensure_target_can_read(path: &Path) -> Result<()> {
    let readable = target_test("-r", path)?;
    ensure!(
        readable,
        "{FIXED_USER} cannot read --path-env source: {}",
        path.display()
    );
    if path.is_dir() {
        ensure!(
            target_test("-x", path)?,
            "{FIXED_USER} cannot traverse --path-env source: {}",
            path.display()
        );
    }
    Ok(())
}

fn target_test(flag: &str, path: &Path) -> Result<bool> {
    let test = system_program("test")?;
    let status = target_std_command()?
        .arg(&test)
        .arg(flag)
        .arg(path)
        .status()
        .context("failed to check fixed-identity path access")?;
    Ok(status.success())
}

fn root_command<I, S>(program: &str, args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let program_path = system_program(program)?;
    let mut command = if effective_uid() == 0 {
        StdCommand::new(&program_path)
    } else {
        let mut command = StdCommand::new(system_program("sudo")?);
        command.args(["-n", "--"]).arg(&program_path);
        command
    };
    let status = command
        .args(args)
        .status()
        .with_context(|| format!("failed to run privileged {program}"))?;
    ensure!(
        status.success(),
        "privileged {program} exited with {status}"
    );
    Ok(())
}

fn resolve_command(value: &OsStr) -> Result<PathBuf> {
    let path = Path::new(value);
    let resolved = if path.components().count() > 1 {
        canonical_existing(path)?
    } else {
        find_on_path(value).context("target command not found on PATH")?
    };
    let metadata = fs::metadata(&resolved)?;
    ensure!(
        metadata.is_file(),
        "target command is not a regular file: {}",
        resolved.display()
    );
    ensure!(
        metadata.permissions().mode() & 0o111 != 0,
        "target command is not executable: {}",
        resolved.display()
    );
    Ok(resolved)
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
            .and_then(|candidate| candidate.canonicalize().ok())
    })
}

fn canonical_existing(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("path does not exist: {}", path.display()))
}

fn copy_read_only(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "--copy-env does not accept symbolic links: {}",
        source.display()
    );
    if metadata.is_dir() {
        fs::create_dir(destination)?;
        set_mode(destination, 0o750)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_read_only(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else {
        ensure!(
            metadata.is_file(),
            "--copy-env accepts only regular files or directories: {}",
            source.display()
        );
        fs::copy(source, destination)?;
        set_mode(destination, 0o640)?;
    }
    Ok(())
}

fn validate_relative(path: &Path) -> Result<()> {
    ensure!(
        !path.as_os_str().is_empty() && !path.is_absolute(),
        "--write-dir must be a non-empty relative path"
    );
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "--write-dir must be a normalized relative path: {}",
        path.display()
    );
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "target stage must not contain symbolic links"
    );
    if metadata.is_dir() {
        set_mode(path, directory_mode)?;
        for entry in fs::read_dir(path)? {
            set_tree_mode(&entry?.path(), directory_mode, file_mode)?;
        }
    } else {
        set_mode(path, file_mode)?;
    }
    Ok(())
}

async fn terminate_target(child: &mut Child) {
    if let Err(error) = child.start_kill() {
        eprintln!("failed to terminate fixed-user target: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_directory_must_be_normalized_and_relative() {
        assert!(validate_relative(Path::new("logs/output")).is_ok());
        assert!(validate_relative(Path::new("../logs")).is_err());
        assert!(validate_relative(Path::new("/tmp/logs")).is_err());
        assert!(validate_relative(Path::new("")).is_err());
    }

    #[test]
    fn target_identity_is_numeric_and_does_not_use_host_account_resolution() {
        assert_eq!(
            target_identity_args(),
            ["--reuid", "998", "--regid", "998", "--clear-groups", "--",].map(OsString::from)
        );
    }
}
