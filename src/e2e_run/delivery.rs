use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::process::Command;

use anyhow::{Context, Result, ensure};

use super::model::{ManagedPathProjectConfig, TargetBuildContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedDirectory {
    pub(crate) root: PathBuf,
    pub(crate) target_relative: PathBuf,
    pub(crate) repository_relative: PathBuf,
}

pub(super) struct ResolvedManagedPaths {
    pub(super) paths: Vec<PathBuf>,
    pub(super) build_contexts: Vec<TargetBuildContext>,
    directories: Vec<ManagedDirectory>,
}

pub(crate) fn resolve_managed_directories(target_root: &Path) -> Result<Vec<ManagedDirectory>> {
    let target_root = fs::canonicalize(target_root)
        .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
    let config_path = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(super::config::PROJECT_CONFIG_FILE);
    let managed_paths = if config_path.is_file() {
        super::config::load_project_config(&target_root, &config_path)?
            .project
            .delivery
            .managed_paths
    } else {
        Vec::new()
    };
    Ok(resolve_project_managed_paths(&target_root, &managed_paths)?.directories)
}

pub(super) fn resolve_project_managed_paths(
    target_root: &Path,
    configured: &[ManagedPathProjectConfig],
) -> Result<ResolvedManagedPaths> {
    let paths = configured
        .iter()
        .map(|entry| entry.path().to_path_buf())
        .collect::<Vec<_>>();
    let directories = managed_directories(target_root, &paths)?;
    let build_contexts = configured
        .iter()
        .zip(directories.iter().skip(1))
        .filter_map(|(entry, directory)| {
            entry.build_context().map(|name| TargetBuildContext {
                name: name.to_string(),
                root: directory.root.clone(),
            })
        })
        .collect();
    Ok(ResolvedManagedPaths {
        paths,
        build_contexts,
        directories,
    })
}

/// Resolve the target plus its configured, disjoint delivery directories.
/// Additional paths are target-relative but may use leading `..` components
/// to select siblings in the same Git repository.
pub(super) fn managed_directories(
    target_root: &Path,
    additional: &[PathBuf],
) -> Result<Vec<ManagedDirectory>> {
    let target_root = fs::canonicalize(target_root)
        .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
    let repository_root = crate::repository::git_root(&target_root)?;
    let mut roots = Vec::with_capacity(additional.len() + 1);
    roots.push(managed_directory(
        &target_root,
        &repository_root,
        &target_root,
    )?);
    let mut seen = BTreeSet::from([target_root.clone()]);
    for configured in additional {
        ensure!(
            !configured.as_os_str().is_empty() && !configured.is_absolute(),
            "delivery.managed_paths entries must be non-empty target-relative paths"
        );
        let resolved = fs::canonicalize(target_root.join(configured)).with_context(|| {
            format!(
                "failed to resolve delivery.managed_paths entry {}",
                configured.display()
            )
        })?;
        ensure!(
            resolved.is_dir(),
            "delivery.managed_paths entry must be a directory: {}",
            configured.display()
        );
        ensure!(
            crate::repository::git_root(&resolved)? == repository_root,
            "delivery.managed_paths entry must belong to the target Git repository: {}",
            configured.display()
        );
        ensure!(
            seen.insert(resolved.clone()),
            "delivery.managed_paths entry resolves to a duplicate directory: {}",
            configured.display()
        );
        ensure!(
            roots.iter().all(|existing| {
                !resolved.starts_with(&existing.root) && !existing.root.starts_with(&resolved)
            }),
            "delivery.managed_paths entries must not overlap the target or each other: {}",
            configured.display()
        );
        roots.push(managed_directory(
            &target_root,
            &repository_root,
            &resolved,
        )?);
    }
    Ok(roots)
}

pub(super) fn validate_managed_path(path: &Path) -> bool {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return false;
    }
    let mut normal_seen = false;
    for component in path.components() {
        match component {
            Component::ParentDir if !normal_seen => {}
            Component::Normal(_) => normal_seen = true,
            _ => return false,
        }
    }
    normal_seen
}

pub(super) fn validate_build_context_name(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    name.len() <= 64
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '_' | '-')
        })
}

fn managed_directory(
    target_root: &Path,
    repository_root: &Path,
    root: &Path,
) -> Result<ManagedDirectory> {
    let repository_relative = root
        .strip_prefix(repository_root)
        .context("managed directory is outside the target Git repository")?
        .to_path_buf();
    Ok(ManagedDirectory {
        root: root.to_path_buf(),
        target_relative: relative_path(target_root, root),
        repository_relative,
    })
}

fn relative_path(from: &Path, to: &Path) -> PathBuf {
    let from = from.components().collect::<Vec<_>>();
    let to = to.components().collect::<Vec<_>>();
    let shared = from
        .iter()
        .zip(&to)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in shared..from.len() {
        relative.push("..");
    }
    for component in &to[shared..] {
        relative.push(component.as_os_str());
    }
    relative
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_disjoint_sibling_in_the_target_repository() {
        let repository = tempfile::tempdir().unwrap();
        let target = repository.path().join("backend-rs-intra");
        let sibling = repository.path().join("backend-rs");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&sibling).unwrap();
        git(repository.path(), &["init", "-q"]);

        let managed = managed_directories(&target, &[PathBuf::from("../backend-rs")]).unwrap();

        assert_eq!(managed.len(), 2);
        assert_eq!(managed[0].root, fs::canonicalize(&target).unwrap());
        assert!(managed[0].target_relative.as_os_str().is_empty());
        assert_eq!(managed[1].root, fs::canonicalize(&sibling).unwrap());
        assert_eq!(managed[1].target_relative, Path::new("../backend-rs"));
        assert_eq!(managed[1].repository_relative, Path::new("backend-rs"));
    }

    #[test]
    fn resolves_opt_in_build_contexts_without_changing_path_scope() {
        let repository = tempfile::tempdir().unwrap();
        let target = repository.path().join("service");
        let sibling = repository.path().join("shared");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&sibling).unwrap();
        git(repository.path(), &["init", "-q"]);
        let configured = vec![ManagedPathProjectConfig::BuildContext(
            super::super::model::ManagedBuildContextProjectConfig {
                path: PathBuf::from("../shared"),
                build_context: "shared-source".to_string(),
            },
        )];

        let resolved = resolve_project_managed_paths(&target, &configured).unwrap();

        assert_eq!(resolved.paths, vec![PathBuf::from("../shared")]);
        assert_eq!(resolved.build_contexts.len(), 1);
        assert_eq!(resolved.build_contexts[0].name, "shared-source");
        assert_eq!(resolved.build_contexts[0].root, sibling);
    }

    #[test]
    fn rejects_overlapping_or_external_managed_directories() {
        let repository = tempfile::tempdir().unwrap();
        let target = repository.path().join("backend-rs-intra");
        fs::create_dir_all(target.join("nested")).unwrap();
        git(repository.path(), &["init", "-q"]);
        assert!(managed_directories(&target, &[PathBuf::from("nested")]).is_err());

        let external = tempfile::tempdir().unwrap();
        git(external.path(), &["init", "-q"]);
        let relative = relative_path(&target, external.path());
        assert!(managed_directories(&target, &[relative]).is_err());
    }

    #[test]
    fn managed_config_paths_require_normalized_leading_parents() {
        assert!(validate_managed_path(Path::new("../backend-rs")));
        assert!(validate_managed_path(Path::new("../../services/backend")));
        assert!(!validate_managed_path(Path::new(".")));
        assert!(!validate_managed_path(Path::new("backend/../sibling")));
        assert!(!validate_managed_path(Path::new("/tmp/backend")));
    }

    #[test]
    fn build_context_names_are_stable_docker_identifiers() {
        assert!(validate_build_context_name("shared-source"));
        assert!(validate_build_context_name("dependency_2.0"));
        assert!(!validate_build_context_name(""));
        assert!(!validate_build_context_name("Shared"));
        assert!(!validate_build_context_name("../shared"));
        assert!(!validate_build_context_name(&"a".repeat(65)));
    }

    fn git(root: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
