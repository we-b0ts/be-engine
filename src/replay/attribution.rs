//! Freeze independently proven ownership into session-local reference views.
//! Original bytes remain immutable; no proof is evaluated in request matching.
use super::*;
use crate::dependency::{
    attribution::DependencyOwner,
    observation::{SCOPE_SCHEMA, ScopeIndex, ScopeKind},
};
use crate::dependency_index::{recording, scoped};

mod inventory;

pub(super) struct Frozen {
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
) -> Result<Frozen> {
    let Some(root) = recording::root(source) else {
        return Ok(Frozen {
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
    let decisions = target
        .map(|target| crate::rewrite::dependency_attribution_overlay(target, &manifest.run_id))
        .transpose()?
        .unwrap_or_default();
    let digest = crate::policy_evidence::digest(&serde_json::to_vec(&decisions)?);
    let mut frozen = Frozen {
        snapshot: Some(digest.clone()),
        startup: Some(root.join("indexes/startup-scope.json")),
        process: Some(root.join("indexes/process-scope.json")),
        unattributed: Some(root.join("indexes/unattributed-scope.json")),
        batch_scope: Some(super::reconciliation::BatchScope::new(
            &root, &manifest, cases,
        )?),
    };
    if let Some(scope) = &mut frozen.batch_scope {
        scope.inventory = inventory::effective(&root, &manifest, &decisions)?;
    }
    if decisions.is_empty() {
        return Ok(frozen);
    }
    let mut by_exchange = BTreeMap::new();
    for decision in &decisions {
        decision.owner.validate()?;
        ensure!(
            by_exchange
                .insert(decision.exchange_id, &decision.owner)
                .is_none(),
            "conflicting frozen attribution decisions"
        );
        match &decision.owner {
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
            DependencyOwner::Unattributed { .. } => {}
        }
    }
    let mut scopes = Vec::new();
    for input in &manifest.inputs {
        scopes.push(root.join(&input.path).join(scoped::CASE_SCOPE));
    }
    for kind in ["startup", "process", "unattributed"] {
        scopes.push(root.join(format!("indexes/{kind}-scope.json")));
    }
    let mut locations = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for path in scopes {
        if !path.is_file() {
            continue;
        }
        let index: ScopeIndex = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(
            index.schema == SCOPE_SCHEMA,
            "unsupported attribution scope schema"
        );
        for location in index.locations {
            ensure!(
                locations
                    .insert(location.offset, (index.scope.clone(), location))
                    .is_none(),
                "Source dependency occurs in multiple ownership views"
            );
        }
    }
    let destination = output
        .join("dependency-scopes")
        .join(digest.trim_start_matches("sha256:"));
    crate::dependency_index::store::private_directory(&destination)?;
    let run_relpath = std::fs::canonicalize(&root)?.to_string_lossy().to_string();
    let mut result: BTreeMap<String, ScopeIndex> = BTreeMap::new();
    for (_, (captured, location)) in locations {
        let scope = if let Some(owner) = by_exchange.get(&location.exchange_id) {
            seen.insert(location.exchange_id);
            match owner {
                DependencyOwner::Case { origin_case_id, .. } => ScopeKind::Case {
                    case_id: *origin_case_id,
                },
                DependencyOwner::Startup { .. } => ScopeKind::Startup,
                DependencyOwner::Process { .. } => ScopeKind::Process,
                DependencyOwner::Unattributed { .. } => ScopeKind::Unattributed,
            }
        } else {
            captured
        };
        let key = match &scope {
            ScopeKind::Case { case_id } => case_id.to_string(),
            ScopeKind::Startup => "startup".into(),
            ScopeKind::Process => "process".into(),
            ScopeKind::Unattributed => "unattributed".into(),
        };
        result
            .entry(key)
            .or_insert_with(|| ScopeIndex {
                schema: SCOPE_SCHEMA.into(),
                run_relpath: run_relpath.clone(),
                scope,
                locations: vec![],
            })
            .locations
            .push(location);
    }
    ensure!(
        seen.len() == by_exchange.len(),
        "attribution refers to absent Source dependency evidence"
    );
    let keys: Vec<_> = cases
        .keys()
        .cloned()
        .chain(["startup".into(), "process".into(), "unattributed".into()])
        .collect();
    for key in keys {
        let scope = result.remove(&key).unwrap_or_else(|| ScopeIndex {
            schema: SCOPE_SCHEMA.into(),
            run_relpath: run_relpath.clone(),
            scope: match key.as_str() {
                "startup" => ScopeKind::Startup,
                "process" => ScopeKind::Process,
                "unattributed" => ScopeKind::Unattributed,
                _ => ScopeKind::Case {
                    case_id: key.parse().expect("manifest Case UUID"),
                },
            },
            locations: vec![],
        });
        let path = destination.join(format!("{key}-scope.json"));
        std::fs::write(&path, serde_json::to_vec(&scope)?)?;
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
