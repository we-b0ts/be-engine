use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, ensure};

use super::config::{CONFIG_VERSION, DEFAULT_RUNTIME_ROOT};
use super::model::{MAX_TARGET_STARTUP_TIMEOUT_SECONDS, ProjectConfig};

pub(super) fn validate_project_config(config: &ProjectConfig) -> Result<()> {
    let project = &config.project;
    ensure!(
        config.version == CONFIG_VERSION,
        "unsupported traffic E2E config version {}; expected {CONFIG_VERSION}",
        config.version
    );
    ensure!(
        project.source.snapshot == Path::new(crate::repository::LOCAL_SOURCE_ROOT),
        "source.snapshot must be {:?}",
        crate::repository::LOCAL_SOURCE_ROOT
    );
    ensure!(
        !project.target.dockerfile.as_os_str().is_empty(),
        "target.dockerfile must not be empty"
    );
    ensure!(
        project.target.dockerfile == Path::new(".traffic-e2e/Dockerfile.target"),
        "target.dockerfile must be .traffic-e2e/Dockerfile.target"
    );
    ensure!(
        (1..=MAX_TARGET_STARTUP_TIMEOUT_SECONDS).contains(&project.target.startup_timeout_seconds),
        "target.startup_timeout_seconds must be between 1 and {MAX_TARGET_STARTUP_TIMEOUT_SECONDS}"
    );
    crate::startup::validate_config(&project.target.startup)?;
    crate::runtime_output::validate_configs(
        &project.target.runtime_outputs,
        &project.target.startup,
    )?;
    project.replay.dependency_loading.validate()?;
    ensure!(
        project.replay.startup_timeout_seconds > 0,
        "replay.startup_timeout_seconds must be positive"
    );
    ensure!(
        !project.policy.as_os_str().is_empty()
            && project.policy.is_relative()
            && project.policy.components().all(|part| matches!(
                part,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )),
        "project.policy must be a non-empty path within the target repository"
    );
    ensure!(
        project.verification.max_failed_cases_per_api > 0,
        "verification.max_failed_cases_per_api must be greater than zero"
    );
    ensure!(
        !project.delivery.pr_base.trim().is_empty(),
        "delivery.pr_base must not be empty"
    );
    ensure!(
        project.delivery.managed_paths.len() <= 7,
        "delivery.managed_paths must contain at most 7 additional directories"
    );
    let mut managed_paths = BTreeSet::new();
    let mut build_contexts = BTreeSet::new();
    for entry in &project.delivery.managed_paths {
        let path = entry.path();
        ensure!(
            super::delivery::validate_managed_path(path),
            "delivery.managed_paths entry must be a normalized target-relative path with any '..' components leading: {}",
            path.display()
        );
        ensure!(
            managed_paths.insert(path),
            "delivery.managed_paths contains duplicate entry: {}",
            path.display()
        );
        if let Some(name) = entry.build_context() {
            ensure!(
                super::delivery::validate_build_context_name(name),
                "delivery.managed_paths build_context must be a lowercase Docker context name of at most 64 ASCII characters: {name:?}"
            );
            ensure!(
                build_contexts.insert(name),
                "delivery.managed_paths contains duplicate build_context: {name:?}"
            );
        }
    }
    ensure!(
        project.state.runtime_root == Path::new(DEFAULT_RUNTIME_ROOT),
        "state.runtime_root must be {DEFAULT_RUNTIME_ROOT:?}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_run::model::{DEFAULT_MAX_FAILED_CASES_PER_API, VerificationProjectConfig};

    #[test]
    fn omitted_failure_limit_uses_the_default() {
        let verification: VerificationProjectConfig = serde_yaml::from_str("{}").unwrap();

        assert_eq!(
            verification.max_failed_cases_per_api,
            DEFAULT_MAX_FAILED_CASES_PER_API
        );
    }

    #[test]
    fn zero_failure_limit_is_rejected() {
        let mut config: ProjectConfig =
            serde_yaml::from_str(include_str!("../../config/project.example.yaml")).unwrap();
        config.project.verification.max_failed_cases_per_api = 0;

        let error = validate_project_config(&config).unwrap_err().to_string();
        assert!(error.contains("must be greater than zero"));
    }
}

#[cfg(test)]
mod dependency_loading_defaults {
    use super::super::model::ReplayProjectConfig;
    #[test]
    fn partial_mapping_preserves_managed_lazy_default() {
        for settings in ["", "dependency_loading: {cache_bytes: 0}\n"] {
            let config: ReplayProjectConfig =
                serde_yaml::from_str(if settings.is_empty() { "{}" } else { settings }).unwrap();
            assert!(config.dependency_loading.lazy_cases);
            assert_eq!(config.startup_timeout_seconds, 60);
        }
        let config: ReplayProjectConfig =
            serde_yaml::from_str("dependency_loading: {lazy_cases: false}\n").unwrap();
        assert!(!config.dependency_loading.lazy_cases);
    }
}
