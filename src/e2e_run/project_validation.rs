use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, ensure};

use super::config::{CONFIG_VERSION, DEFAULT_RUNTIME_ROOT};
use super::model::{MAX_TARGET_STARTUP_TIMEOUT_SECONDS, ProcessOutputSettings, ProjectConfig};
use super::target_quality_config::validate_target_quality_gates;

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
    if let Some(breeze) = &project.breeze {
        ensure!(
            !breeze.container.trim().is_empty(),
            "breeze.container must not be empty"
        );
    }
    let process_outputs = project
        .process_outputs
        .iter()
        .map(ProcessOutputSettings::config)
        .collect::<Vec<_>>();
    crate::process_output::validate_configs(&process_outputs)?;
    ensure!(
        !project.target.dockerfile.as_os_str().is_empty(),
        "target.dockerfile must not be empty"
    );
    ensure!(
        project.target.dockerfile == Path::new(".traffic-e2e/Dockerfile.e2e"),
        "target.dockerfile must be .traffic-e2e/Dockerfile.e2e"
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
    if let Some(gates) = &project.target.quality_gates {
        validate_target_quality_gates(gates)?;
    }
    ensure!(
        !project.replay.policy.as_os_str().is_empty(),
        "replay.policy must not be empty"
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
    ensure!(
        project.recording.source_traffic_policy
            == Path::new(crate::config::SOURCE_TRAFFIC_POLICY_FILE),
        "project.recording.source_traffic_policy must be {:?}",
        crate::config::SOURCE_TRAFFIC_POLICY_FILE
    );
    Ok(())
}
