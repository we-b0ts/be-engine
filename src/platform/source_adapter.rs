use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};

const IMAGE_PREFIX: &str = "traffic-e2e/";
const IMAGE_SUFFIX: &str = "-recording:cache";
const RUNTIME_PREFIX: &str = "traffic-e2e-";
const RUNTIME_SUFFIX: &str = "-recording-runtime-cache";

pub(crate) fn source_revision(target_root: &Path) -> Result<String> {
    let image = image_tag(target_root)?;
    docker_identity(
        &["image", "inspect", "--format", "{{.Id}}", &image],
        &format!("recording source adaptor image {image:?}"),
    )
}

pub(crate) fn source_runtime_revision(target_root: &Path) -> Result<String> {
    let runtime = runtime_template_name(target_root)?;
    docker_identity(
        &[
            "container",
            "inspect",
            "--format",
            "{{.Id}}:{{.Image}}",
            &runtime,
        ],
        &format!("recording source adaptor runtime template {runtime:?}"),
    )
}

fn image_tag(target_root: &Path) -> Result<String> {
    Ok(format!(
        "{IMAGE_PREFIX}{}{IMAGE_SUFFIX}",
        normalized_project_name(target_root)?
    ))
}

fn runtime_template_name(target_root: &Path) -> Result<String> {
    Ok(format!(
        "{RUNTIME_PREFIX}{}{RUNTIME_SUFFIX}",
        normalized_project_name(target_root)?
    ))
}

fn normalized_project_name(target_root: &Path) -> Result<String> {
    let name = crate::repository::directory_name(target_root)?;
    let mut normalized = String::with_capacity(name.len());
    let mut previous_dash = false;
    for character in name.chars() {
        let character = character.to_ascii_lowercase();
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_') {
            normalized.push(character);
            previous_dash = false;
        } else if !previous_dash {
            normalized.push('-');
            previous_dash = true;
        }
    }
    let normalized = normalized.trim_matches('-');
    ensure!(
        !normalized.is_empty(),
        "target repository name cannot form a recording source adaptor name"
    );
    Ok(normalized.to_string())
}

fn docker_identity(args: &[&str], label: &str) -> Result<String> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .with_context(|| format!("failed to inspect {label}"))?;
    ensure!(
        output.status.success(),
        "failed to inspect {label}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let identity = String::from_utf8(output.stdout)
        .with_context(|| format!("{label} identity is not UTF-8"))?
        .trim()
        .to_string();
    ensure!(!identity.is_empty(), "{label} has no immutable identity");
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_the_managed_runtime_contract() {
        let root = Path::new("/tmp/Service Graph@RS");
        assert_eq!(
            image_tag(root).unwrap(),
            "traffic-e2e/service-graph-rs-recording:cache"
        );
        assert_eq!(
            runtime_template_name(root).unwrap(),
            "traffic-e2e-service-graph-rs-recording-runtime-cache"
        );
    }

    #[test]
    fn normalization_matches_the_shell_name_rules() {
        assert_eq!(
            normalized_project_name(Path::new("/tmp/a-@@b")).unwrap(),
            "a-b"
        );
        assert_eq!(
            normalized_project_name(Path::new("/tmp/a._@@b")).unwrap(),
            "a._-b"
        );
    }
}
