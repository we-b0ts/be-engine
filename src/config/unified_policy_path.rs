//! Resolve the sole public policy path without loading the policy or Source.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::path::{Component, Path, PathBuf};

#[derive(Deserialize)]
struct Document {
    project: Reference,
}
#[derive(Deserialize)]
struct Reference {
    policy: PathBuf,
}

pub fn resolve_unified_policy_path(project_path: &Path) -> Result<PathBuf> {
    let document: Document =
        serde_yaml::from_slice(&std::fs::read(project_path).with_context(|| {
            format!(
                "failed to read project policy reference {}",
                project_path.display()
            )
        })?)
        .context("project.policy must name the unified traffic policy")?;
    let policy = document.project.policy;
    ensure!(
        !policy.as_os_str().is_empty()
            && policy.is_relative()
            && policy
                .components()
                .all(|part| matches!(part, Component::Normal(_) | Component::CurDir)),
        "project.policy must be a non-empty path within the target repository"
    );
    let directory = project_path
        .parent()
        .context("project config has no directory")?;
    ensure!(
        directory
            .file_name()
            .is_some_and(|name| name == crate::repository::TRAFFIC_E2E_ROOT),
        "managed project config must be located under .traffic-e2e"
    );
    let root = directory
        .parent()
        .context("project config has no target repository root")?;
    let root = std::fs::canonicalize(if root.as_os_str().is_empty() {
        Path::new(".")
    } else {
        root
    })?;
    let normalized = policy
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value),
            _ => None,
        })
        .collect::<PathBuf>();
    ensure!(
        !normalized.as_os_str().is_empty(),
        "project.policy must name a file"
    );
    Ok(root.join(normalized))
}

/// Locate the managed repository that explicitly authorizes this policy. The
/// policy may live anywhere inside that repository, so its parent is not an
/// ownership or encryption-key boundary.
pub(crate) fn resolve_unified_policy_root(policy: &Path) -> Result<PathBuf> {
    let policy = std::fs::canonicalize(policy)
        .with_context(|| format!("failed to resolve policy {}", policy.display()))?;
    let mut roots = std::collections::BTreeSet::new();
    for root in policy
        .parent()
        .context("policy has no parent directory")?
        .ancestors()
    {
        let project = root
            .join(crate::repository::TRAFFIC_E2E_ROOT)
            .join("project.yaml");
        if !project.is_file() {
            continue;
        }
        let Ok(reference) = resolve_unified_policy_path(&project) else {
            continue;
        };
        let Ok(reference) = std::fs::canonicalize(reference) else {
            continue;
        };
        if reference == policy {
            roots.insert(root.to_owned());
        }
    }
    ensure!(
        roots.len() == 1,
        "policy {} must be authorized by exactly one managed project.policy reference",
        policy.display()
    );
    Ok(roots.into_iter().next().expect("one authorized root"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolves_target_relative_policy_before_it_exists_and_rejects_escape_or_old_fields() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join(".traffic-e2e");
        std::fs::create_dir(&directory).unwrap();
        let project = directory.join("project.yaml");
        std::fs::write(&project, "project:\n  policy: .traffic-e2e/policy.yaml\n").unwrap();
        assert_eq!(
            resolve_unified_policy_path(&project).unwrap(),
            temp.path().join(".traffic-e2e/policy.yaml")
        );
        for raw in [
            "project:\n  policy: ../outside.yaml\n",
            "project:\n  policy: /tmp/outside.yaml\n",
            "project:\n  recording: {source_traffic_policy: old.yaml}\n",
        ] {
            std::fs::write(&project, raw).unwrap();
            assert!(resolve_unified_policy_path(&project).is_err());
        }
    }
}
