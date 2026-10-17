//! Canonical final-review commands, executed serially with private local logs.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use serde::Serialize;

use super::{QualityCommandReport, QualityCommandStatus};

pub(super) const POLICY_VERSION: &str = "final-rust-quality-v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct CommandSpec {
    pub name: String,
    pub argv: Vec<String>,
    pub working_directory: PathBuf,
}

// Project loading has already validated that managed directories are disjoint
// and belong to the same repository. Non-Rust directories add no Cargo gates.
pub(super) fn inferred(root: &Path, managed_paths: &[PathBuf]) -> Vec<CommandSpec> {
    std::iter::once(PathBuf::from("."))
        .chain(managed_paths.iter().cloned())
        .enumerate()
        .filter(|(_, path)| root.join(path).join("Cargo.toml").is_file())
        .flat_map(|(index, path)| rust_gates((index != 0).then_some(index), &path))
        .collect()
}

fn rust_gates(managed_index: Option<usize>, working_directory: &Path) -> Vec<CommandSpec> {
    let name = |suffix: &str| match managed_index {
        Some(index) => format!("managed-{index}-rust-{suffix}"),
        None => format!("rust-{suffix}"),
    };
    [
        ("format", vec!["fmt", "--all", "--check"]),
        ("test", vec!["test", "--workspace"]),
        (
            "clippy",
            vec![
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        ),
    ]
    .into_iter()
    .map(|(suffix, args)| {
        // Execute from the manifest directory so Cargo reads that project's
        // .cargo/config.toml and rust-toolchain files, including managed siblings.
        let argv = std::iter::once("cargo".to_string())
            .chain(args.into_iter().map(str::to_string))
            .collect();
        CommandSpec {
            name: name(suffix),
            argv,
            working_directory: working_directory.to_path_buf(),
        }
    })
    .collect()
}

pub(super) fn run(root: &Path, gates: &[CommandSpec]) -> Result<Vec<QualityCommandReport>> {
    if gates.is_empty() {
        return Ok(Vec::new());
    }
    let root = fs::canonicalize(root).context("failed to resolve quality check worktree")?;
    let log_root = crate::internal_runtime::root(&root)
        .join("rewrite/quality")
        .join(uuid::Uuid::new_v4().simple().to_string());
    fs::create_dir_all(&log_root).context("failed to create quality gate log directory")?;
    let mut reports = Vec::with_capacity(gates.len());
    for (index, gate) in gates.iter().enumerate() {
        let log_path = log_root.join(format!("{index}.log"));
        let mut log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&log_path)
            .context("failed to create quality gate log")?;
        let mut report = QualityCommandReport {
            name: gate.name.clone(),
            argv: gate.argv.clone(),
            working_directory: gate.working_directory.clone(),
            status: QualityCommandStatus::Failed,
            exit_code: None,
            log_path,
            error: None,
        };
        let result = match gate.argv.split_first() {
            Some((executable, arguments)) if !executable.trim().is_empty() => {
                Command::new(executable)
                    .args(arguments)
                    .current_dir(root.join(&gate.working_directory))
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(log.try_clone()?))
                    .stderr(Stdio::from(log.try_clone()?))
                    .status()
                    .with_context(|| format!("failed to execute quality gate {:?}", gate.name))
            }
            _ => Err(anyhow::anyhow!(
                "quality gate {:?} has no executable",
                gate.name
            )),
        };
        match result {
            Ok(status) => {
                report.exit_code = status.code();
                if status.success() {
                    report.status = QualityCommandStatus::Passed;
                } else {
                    report.error = Some(status.to_string());
                }
            }
            Err(error) => report.error = Some(format!("{error:#}")),
        }
        if let Some(error) = &report.error {
            writeln!(log, "\nquality gate execution failed: {error}")?;
        }
        log.sync_all().context("failed to flush quality gate log")?;
        let passed = report.passed();
        reports.push(report);
        if !passed {
            break;
        }
    }
    Ok(reports)
}
