//! Host-supplied workflow ownership for execution and administrator operations.
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, OnceLock},
};
use traffic_model::attribution::DependencyOwner;
use uuid::Uuid;

pub type FrozenAttribution = (BTreeMap<Uuid, DependencyOwner>, String);
pub type SourceUpgradeGuard = Box<dyn Send>;

/// The application installs a stateless coordinator. Every operation supplies
/// its own Target root, so concurrent projects retain independent workflow state.
pub trait Coordinator: Send + Sync {
    fn freeze(&self, target: Option<&Path>, source: &Path, run: &str) -> Result<FrozenAttribution>;
    fn identity(&self, target: &Path, source: Option<&Path>, run: &str) -> Result<String>;
    fn lock_source_upgrade(&self, target: &Path) -> Result<SourceUpgradeGuard>;
}

static COORDINATOR: OnceLock<Arc<dyn Coordinator>> = OnceLock::new();

pub fn initialize(factory: impl FnOnce() -> Arc<dyn Coordinator>) {
    COORDINATOR.get_or_init(factory);
}

pub fn freeze_dependency_attribution(
    target: Option<&Path>,
    source: &Path,
    run: &str,
) -> Result<FrozenAttribution> {
    if let Some(coordinator) = COORDINATOR.get() {
        return coordinator.freeze(target, source, run);
    }
    standalone_attribution(target, source, run)
}

pub fn dependency_attribution_identity_for_source(
    target: &Path,
    source: &Path,
    run: &str,
) -> Result<String> {
    if let Some(coordinator) = COORDINATOR.get() {
        return coordinator.identity(target, Some(source), run);
    }
    Ok(standalone_attribution(Some(target), source, run)?.1)
}

#[allow(dead_code)]
#[cfg(test)]
pub fn dependency_attribution_snapshot(target: &Path, run: &str) -> Result<String> {
    if let Some(coordinator) = COORDINATOR.get() {
        return coordinator.identity(target, None, run);
    }
    let source = target
        .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
        .join("recordings")
        .join(run);
    Ok(standalone_attribution(Some(target), &source, run)?.1)
}

pub fn lock_admin_source_upgrade(target: &Path) -> Result<SourceUpgradeGuard> {
    COORDINATOR
        .get()
        .context("Source upgrade requires the application's workflow coordinator")?
        .lock_source_upgrade(target)
}

fn standalone_attribution(
    target: Option<&Path>,
    source: &Path,
    run: &str,
) -> Result<FrozenAttribution> {
    if let Some(target) = target {
        ensure!(
            !crate::internal_runtime::root(target)
                .join("rewrite/state.json")
                .exists(),
            "workflow-owned recording requires the application's workflow coordinator"
        );
    }
    let (root, manifest) = crate::dependency_index::recording::manifest(source)?;
    ensure!(
        manifest.sealed && manifest.run_id == run,
        "Source recording inventory is not the current sealed workflow input"
    );
    let bytes = std::fs::read(root.join(crate::dependency::observation::MANIFEST_FILE))?;
    let inventory = crate::policy_evidence::digest(&bytes);
    let owners = crate::attribution_defaults::load(source, target)?;
    let mut identity = traffic_recording_store::attribution::snapshot_identity(
        run,
        None,
        &inventory,
        &[] as &[()],
    )?;
    if !owners.is_empty() {
        identity = crate::policy_evidence::digest(&serde_json::to_vec(&(
            "case-window-notification-ownership/v1",
            identity,
            &owners,
        ))?);
    }
    Ok((owners, identity))
}
