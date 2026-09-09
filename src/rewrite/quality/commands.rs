//! Executes the canonical argv in the delivery worktree and retains local logs.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::e2e_run::TargetQualityGateConfig;

use super::{QualityCommandReport, QualityCommandStatus};

pub(super) fn run(
    root: &Path,
    gates: &[TargetQualityGateConfig],
) -> Result<Vec<QualityCommandReport>> {
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
            status: QualityCommandStatus::Failed,
            exit_code: None,
            log_path,
            error: None,
        };
        let result = match gate.argv.split_first() {
            Some((executable, arguments)) if !executable.trim().is_empty() => {
                Command::new(executable)
                    .args(arguments)
                    .current_dir(&root)
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
