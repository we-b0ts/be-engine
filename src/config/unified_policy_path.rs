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
    let policy = root.join(normalized);
    validate_ownership(&root, &policy)?;
    Ok(policy)
}

fn validate_ownership(root: &Path, policy: &Path) -> Result<()> {
    let mut checked = false;
    for ancestor in policy.ancestors().take_while(|path| path.starts_with(root)) {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect policy path {}", ancestor.display())
                });
            }
        };
        // Parent aliases would give the policy a second repository path and
        // disagree with code-fingerprint exclusions. A leaf is left unchanged
        // so the Source owner's regular-file check still rejects leaf links.
        ensure!(
            ancestor == policy || !metadata.file_type().is_symlink(),
            "project.policy parent directories must not be symlinks: {}",
            ancestor.display()
        );
        if !checked {
            let canonical = std::fs::canonicalize(ancestor).with_context(|| {
                format!(
                    "failed to resolve existing policy path {}",
                    ancestor.display()
                )
            })?;
            ensure!(
                canonical.starts_with(root),
                "project.policy must remain within the target repository"
            );
            checked = true;
        }
    }
    ensure!(
        checked,
        "project.policy has no existing repository ancestor"
    );
    Ok(())
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

    #[test]
    fn missing_nested_policy_is_supported_but_parent_links_cannot_change_ownership() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(outside.path().join("nested")).unwrap();
        std::fs::write(
            outside.path().join("nested/rules.yaml"),
            "format: traffic-policy/v3\nrules: []\n",
        )
        .unwrap();
        let managed = temp.path().join(".traffic-e2e");
        std::fs::create_dir(&managed).unwrap();
        let project = managed.join("project.yaml");
        std::fs::write(
            &project,
            "project:\n  policy: contracts/nested/rules.yaml\n",
        )
        .unwrap();
        assert_eq!(
            resolve_unified_policy_path(&project).unwrap(),
            temp.path().join("contracts/nested/rules.yaml")
        );
        for target in [
            outside.path().to_path_buf(),
            temp.path().join("missing-parent"),
        ] {
            std::os::unix::fs::symlink(&target, temp.path().join("contracts")).unwrap();
            assert!(resolve_unified_policy_path(&project).is_err());
            std::fs::remove_file(temp.path().join("contracts")).unwrap();
        }
        std::fs::create_dir(temp.path().join("inside")).unwrap();
        std::os::unix::fs::symlink(temp.path().join("inside"), temp.path().join("contracts"))
            .unwrap();
        assert!(
            resolve_unified_policy_path(&project).is_err(),
            "parent aliases inside the repository are also rejected"
        );
    }

    #[test]
    fn existing_policy_has_one_authorized_root_and_leaf_links_stay_visible_to_source() {
        let temp = tempfile::tempdir().unwrap();
        let managed = temp.path().join(".traffic-e2e");
        std::fs::create_dir(&managed).unwrap();
        let project = managed.join("project.yaml");
        std::fs::write(&project, "project:\n  policy: contracts/rules.yaml\n").unwrap();
        let directory = temp.path().join("contracts");
        std::fs::create_dir(&directory).unwrap();
        let policy = directory.join("rules.yaml");
        std::fs::write(&policy, "format: traffic-policy/v3\nrules: []\n").unwrap();
        assert_eq!(resolve_unified_policy_path(&project).unwrap(), policy);
        assert_eq!(resolve_unified_policy_root(&policy).unwrap(), temp.path());
        std::fs::rename(&policy, directory.join("actual.yaml")).unwrap();
        std::os::unix::fs::symlink("actual.yaml", &policy).unwrap();
        assert_eq!(resolve_unified_policy_path(&project).unwrap(), policy);
        assert!(
            crate::config::SourceTrafficPolicyConfig::load(&policy)
                .unwrap_err()
                .to_string()
                .contains("regular file")
        );
    }
}
