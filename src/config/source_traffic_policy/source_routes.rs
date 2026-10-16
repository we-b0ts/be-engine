//! Additive, serialized publication of confirmed method-specific HTTP routes.
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    path::Path,
};

use anyhow::{Context, Result, ensure};

use crate::config::{AppConfig, HttpSourceRoutes, SourceTrafficPolicyConfig};

pub(crate) fn register(
    project_config: &Path,
    policy_path: &Path,
    registrations: impl IntoIterator<Item = String>,
) -> Result<HttpSourceRoutes> {
    let lock_path = project_config
        .parent()
        .context("project config has no parent")?
        .join("local/runtime/locks/source-routes.lock");
    fs::create_dir_all(lock_path.parent().expect("lock has parent"))?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    lock.lock()
        .context("failed to lock Source route registrations")?;
    let original = fs::read_to_string(policy_path)?;
    let mut policy = SourceTrafficPolicyConfig::parse(&original, policy_path)?;
    let routes = policy.http.source_routes.merged(registrations)?;
    let original_project = fs::read_to_string(project_config)?;
    // Managed patterns and other policy values must be applied before checking
    // cross-field constraints such as dynamic per-API limit overrides.
    let mut config = AppConfig::parse_static(project_config, &original_project)?;
    ensure!(
        routes
            .entries()
            .all(|api| api.is_covered_by(&config.http_gateway.rules)),
        "HTTP Source registration is outside the configured recording method/path scope"
    );
    policy.http.source_routes = routes.clone();
    policy.http.case_path_patterns = policy
        .http
        .case_path_patterns
        .iter()
        .cloned()
        .chain(
            routes
                .entries()
                .filter(|api| api.is_dynamic())
                .map(|api| api.path_pattern().to_owned()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    policy.apply_to(&mut config)?;
    config.validate()?;
    let updated = policy.render()?;
    ensure!(
        fs::read_to_string(policy_path)? == original,
        "source traffic policy changed during Source registration; retry the current action"
    );
    ensure!(
        fs::read_to_string(project_config)? == original_project,
        "project config changed during Source registration; retry the current action"
    );
    if original != updated {
        crate::config::edit::write_atomic(policy_path, updated.as_bytes())?;
    }
    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn managed_policy_is_loaded_before_validating_dynamic_limit_overrides() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project.yaml");
        let policy = temp.path().join("source-traffic-policy.yaml");
        fs::write(&project, "project:\n  recording:\n    source_traffic_policy: source-traffic-policy.yaml\nrecorder:\n  http_gateway:\n    per_api_case_limits:\n      overrides:\n        /items/*: 5\n").unwrap();
        let mut initial = SourceTrafficPolicyConfig::empty();
        initial.http.case_path_patterns = vec!["/items/*".into()];
        fs::write(&policy, initial.render().unwrap()).unwrap();
        register(&project, &policy, ["GET /items/*".into()]).unwrap();
        let config = AppConfig::load(&project).unwrap();
        assert_eq!(
            config.http_gateway.per_api_case_limits.overrides["/items/*"],
            5
        );
        assert!(
            config
                .http_gateway
                .source_routes
                .resolve("GET", "/items/7")
                .is_some()
        );
    }

    #[test]
    fn concurrent_registrations_preserve_static_and_pattern_without_lost_updates() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project.yaml");
        let policy = temp.path().join("source-traffic-policy.yaml");
        fs::write(&project, "project:\n  recording:\n    source_traffic_policy: source-traffic-policy.yaml\nrecorder: {}\n").unwrap();
        fs::write(
            &policy,
            SourceTrafficPolicyConfig::empty().render().unwrap(),
        )
        .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let threads = ["GET /items/upload", "GET /items/*"].map(|source| {
            let (project, policy, barrier) = (project.clone(), policy.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                register(&project, &policy, [source.to_owned()]).unwrap();
            })
        });
        for thread in threads {
            thread.join().unwrap();
        }
        let result = SourceTrafficPolicyConfig::load(&policy).unwrap();
        assert_eq!(result.http.source_routes.entries().count(), 2);
        assert_eq!(
            result
                .http
                .source_routes
                .resolve("GET", "/items/upload")
                .unwrap()
                .to_string(),
            "GET /items/upload"
        );
    }
}
