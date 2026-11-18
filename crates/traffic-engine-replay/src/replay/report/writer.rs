use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use super::dependency_evidence::{build_dependency_evidence, dependency_evidence_path};

pub async fn clear_report_artifacts(report_path: Option<&Path>) -> Result<()> {
    let Some(report_path) = report_path else {
        return Ok(());
    };
    for path in [
        report_path.to_path_buf(),
        dependency_evidence_path(report_path),
    ] {
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to clear stale replay artifact {}", path.display())
                });
            }
        }
    }
    Ok(())
}

pub async fn write_final_report_value(
    report_path: PathBuf,
    report: &Value,
    codecs: &traffic_protocol::report::CodecRegistry,
) -> Result<()> {
    write_report_value(&report_path, report).await?;
    let evidence = build_dependency_evidence(report, codecs);
    if let Err(error) = write_report_value(&dependency_evidence_path(&report_path), &evidence).await
    {
        let _ = clear_report_artifacts(Some(&report_path)).await;
        return Err(error);
    }
    Ok(())
}

pub async fn write_report_value(report_path: &Path, report: &impl Serialize) -> Result<()> {
    if let Some(parent) = report_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create replay report dir {}", parent.display()))?;
    }
    let mut payload = serde_json::to_vec(report).context("failed to serialize replay report")?;
    payload.push(b'\n');
    let file_name = report_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("replay-report.json");
    let temporary_path = report_path.with_file_name(format!(".{file_name}.{}.tmp", Uuid::new_v4()));
    tokio::fs::write(&temporary_path, payload)
        .await
        .with_context(|| {
            format!(
                "failed to write temporary replay report {}",
                temporary_path.display()
            )
        })?;
    if let Err(error) = tokio::fs::rename(&temporary_path, report_path).await {
        let _ = tokio::fs::remove_file(&temporary_path).await;
        return Err(error)
            .with_context(|| format!("failed to publish replay report {}", report_path.display()));
    }
    Ok(())
}
