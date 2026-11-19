//! Freeze independently proven ownership into session-local reference views.
//! Original bytes remain immutable; no proof is evaluated in request matching.
use super::*;
use crate::dependency::attribution::DependencyOwner;
use crate::dependency_index::recording;

mod inventory;
#[cfg(test)]
mod tests;

use traffic_engine::replay::attribution::views;

pub(super) struct Frozen {
    pub run_value_scopes: BTreeMap<Uuid, Arc<str>>,
    pub snapshot: Option<String>,
    pub startup: Option<PathBuf>,
    pub process: Option<PathBuf>,
    pub unattributed: Option<PathBuf>,
    pub batch_scope: Option<super::reconciliation::BatchScope>,
}

pub(super) fn freeze(
    source: &Path,
    output: &Path,
    cases: &mut BTreeMap<String, ReplayCase>,
    evidence: &traffic_protocol::evidence::EvidenceRegistry,
) -> Result<Frozen> {
    let Some(root) = recording::root(source) else {
        return Ok(Frozen {
            run_value_scopes: BTreeMap::new(),
            snapshot: None,
            startup: super::find_run_level_dependencies(source).0,
            process: None,
            unattributed: None,
            batch_scope: None,
        });
    };
    let (_, manifest) = recording::manifest(&root)?;
    let target = root
        .ancestors()
        .find(|path| path.join(".traffic-e2e").is_dir());
    let (decisions, digest) = crate::coordination::freeze_dependency_attribution_for_replay(
        target,
        &root,
        &manifest.run_id,
    )?;
    let mut frozen = Frozen {
        run_value_scopes: BTreeMap::new(),
        snapshot: Some(digest.clone()),
        startup: Some(root.join("indexes/startup-scope.json")),
        process: Some(root.join("indexes/process-scope.json")),
        unattributed: Some(root.join("indexes/unattributed-scope.json")),
        batch_scope: Some(super::reconciliation::BatchScope::new(
            &root, &manifest, cases,
        )?),
    };
    if (!decisions.is_empty()
        || manifest.schema != crate::dependency::observation::COMPACT_RECORDING_SCHEMA)
        && let Some(scope) = &mut frozen.batch_scope
    {
        scope.inventory =
            inventory::effective_with_evidence(&root, &manifest, &decisions, evidence, false)?;
    }
    if decisions.is_empty() {
        return Ok(frozen);
    }
    let by_exchange = &decisions;
    let mut value_scopes = BTreeMap::<String, Arc<str>>::new();
    for (exchange_id, owner) in &decisions {
        owner.validate()?;
        match owner {
            DependencyOwner::Startup { process_epoch, .. }
            | DependencyOwner::Process { process_epoch, .. } => ensure!(
                manifest.process_epochs.contains(process_epoch),
                "attribution refers to a foreign process epoch"
            ),
            DependencyOwner::Case { origin_case_id, .. } => ensure!(
                manifest
                    .inputs
                    .iter()
                    .any(|input| input.case_id == *origin_case_id),
                "attribution refers to an absent origin Case"
            ),
            DependencyOwner::Shutdown {
                process_epoch,
                origin_case_id,
            } => ensure!(
                manifest.process_epochs.contains(process_epoch)
                    && manifest
                        .inputs
                        .iter()
                        .any(|input| input.case_id == *origin_case_id),
                "shutdown attribution refers to an absent process epoch or origin Case"
            ),
            DependencyOwner::Unattributed { .. } => {}
        }
        if let Some(scope) = run_value_scope(owner) {
            let value = value_scopes
                .entry(scope.clone())
                .or_insert_with(|| Arc::from(scope));
            frozen.run_value_scopes.insert(*exchange_id, value.clone());
        }
    }
    let paths = views::freeze(&root, &manifest, output, cases.keys(), by_exchange, &digest)?;
    for (key, path) in paths {
        if let Some(case) = cases.get_mut(&key) {
            case.dependencies_path = path.clone();
        }
        match key.as_str() {
            "startup" => frozen.startup = Some(path),
            "process" => frozen.process = Some(path),
            "unattributed" => frozen.unattributed = Some(path),
            _ => {}
        }
    }
    Ok(frozen)
}

pub(crate) fn run_value_scope(owner: &DependencyOwner) -> Option<String> {
    match owner {
        DependencyOwner::Process {
            process_epoch,
            source_task,
            ..
        } => Some(format!("process:{process_epoch}:{source_task}")),
        DependencyOwner::Startup {
            process_epoch,
            initialization_unit,
        } => Some(format!("startup:{process_epoch}:{initialization_unit}")),
        _ => None,
    }
}
