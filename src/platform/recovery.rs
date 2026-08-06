use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use tokio::process::Command;

use super::ManagedRecordingOperation;

const RECOVERY_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_MATCHED_CONTAINERS: usize = 16;

#[derive(Debug, Clone, Serialize)]
pub struct ManagedRecordingRecoveryResult {
    pub run_id: String,
    pub operation: ManagedRecordingOperation,
    pub removed_containers: usize,
}

pub async fn recover_managed_recording(
    target_root: &Path,
    operation: ManagedRecordingOperation,
    run_id: &str,
) -> Result<ManagedRecordingRecoveryResult> {
    ensure!(
        run_id.len() == 14 && run_id.bytes().all(|byte| byte.is_ascii_digit()),
        "managed recording recovery requires a 14-digit run id"
    );
    let (target_root, _) = crate::e2e_run::resolve_project(target_root)?;
    let repo_name = normalized_repo_name(&target_root)?;
    let prefix = format!(
        "traffic-e2e-{repo_name}-{}-{run_id}-",
        operation.script_name()
    );
    let output = tokio::time::timeout(
        RECOVERY_TIMEOUT,
        Command::new("docker")
            .args([
                "ps",
                "--all",
                "--format",
                "{{.Names}}",
                "--filter",
                &format!("name={prefix}"),
            ])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .context("timed out while discovering managed recording containers")??;
    ensure!(
        output.status.success(),
        "failed to discover managed recording containers: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let stdout = String::from_utf8(output.stdout)
        .context("Docker returned non-UTF-8 managed container names")?;
    let containers = matching_container_names(&stdout, &prefix)?;
    let tokens = containers
        .iter()
        .filter_map(|name| container_token(name, &prefix, run_id))
        .collect::<std::collections::BTreeSet<_>>();

    if !containers.is_empty() {
        let status = tokio::time::timeout(
            RECOVERY_TIMEOUT,
            Command::new("docker")
                .arg("rm")
                .arg("--force")
                .args(&containers)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .status(),
        )
        .await
        .context("timed out while removing managed recording containers")??;
        ensure!(
            status.success(),
            "failed to remove managed recording containers"
        );
    }
    let local = crate::internal_runtime::root(&target_root).join("platform");
    for token in tokens {
        remove_runtime_dir(&local.join("control").join(&token), &local.join("control"))?;
        remove_runtime_dir(
            &local.join("adapters").join(&token),
            &local.join("adapters"),
        )?;
    }
    Ok(ManagedRecordingRecoveryResult {
        run_id: run_id.to_string(),
        operation,
        removed_containers: containers.len(),
    })
}

fn matching_container_names(stdout: &str, prefix: &str) -> Result<Vec<String>> {
    let mut matches = stdout
        .lines()
        .filter(|name| name.starts_with(prefix))
        .filter(|name| {
            name.rsplit_once('-').is_some_and(|(base, role)| {
                matches!(role, "anchor" | "recorder" | "breeze" | "source" | "target")
                    && base.strip_prefix(prefix).is_some_and(|pid| {
                        !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())
                    })
            })
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    ensure!(
        matches.len() <= MAX_MATCHED_CONTAINERS,
        "managed recording recovery matched too many containers"
    );
    Ok(matches)
}

fn container_token(name: &str, prefix: &str, run_id: &str) -> Option<String> {
    let (base, _) = name.rsplit_once('-')?;
    let pid = base.strip_prefix(prefix)?;
    Some(format!("{run_id}-{pid}"))
}

fn normalized_repo_name(target_root: &Path) -> Result<String> {
    let raw = target_root
        .file_name()
        .context("target repository has no directory name")?
        .to_string_lossy();
    let mut normalized = String::with_capacity(raw.len());
    let mut previous_dash = false;
    for character in raw.chars() {
        let accepted = character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-');
        if accepted {
            normalized.push(character);
            previous_dash = character == '-';
        } else if !previous_dash {
            normalized.push('-');
            previous_dash = true;
        }
    }
    let normalized = normalized.trim_matches('-').to_string();
    ensure!(
        !normalized.is_empty(),
        "target repository name cannot form a Docker container prefix"
    );
    Ok(normalized)
}

fn remove_runtime_dir(path: &Path, parent: &Path) -> Result<()> {
    ensure!(
        path.starts_with(parent) && path != parent,
        "refusing to remove an unexpected managed runtime path"
    );
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to remove managed runtime {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_matches_only_the_exact_run_and_known_roles() {
        let prefix = "traffic-e2e-service-record-20260802000000-";
        let names = matching_container_names(
            "traffic-e2e-service-record-20260802000000-123-anchor\n\
             traffic-e2e-service-record-20260802000000-123-recorder\n\
             traffic-e2e-service-record-20260802000001-123-anchor\n\
             traffic-e2e-service-record-20260802000000-not-a-pid-source\n\
             traffic-e2e-service-record-20260802000000-123-unknown\n",
            prefix,
        )
        .unwrap();
        assert_eq!(
            names,
            vec![
                "traffic-e2e-service-record-20260802000000-123-anchor",
                "traffic-e2e-service-record-20260802000000-123-recorder",
            ]
        );
        assert_eq!(
            container_token(&names[0], prefix, "20260802000000").as_deref(),
            Some("20260802000000-123")
        );
    }

    #[test]
    fn repository_name_normalization_matches_the_shell_contract() {
        assert_eq!(
            normalized_repo_name(Path::new("/tmp/service graph@rs")).unwrap(),
            "service-graph-rs"
        );
    }
}
