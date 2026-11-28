//! Matchable exchange events and their recorded ownership around a failed Source event.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use traffic_engine_config::config::api_catalog::{self, ApiCatalog};
use traffic_recording_store::session::{WindowFailureOwner, primary_dispatch_window};

const WINDOW_MICROS: u64 = 60_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchWindow {
    pub from_seq: u64,
    pub through_seq: u64,
    pub apis: Vec<WindowApi>,
    #[serde(default)]
    pub matches: BTreeMap<u64, WindowMatch>,
    pub failure_owner: Option<WindowOwner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowMatch {
    pub kind: WindowMatchKind,
    pub exchange_sequence: u64,
    pub owner: Option<WindowOwner>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowMatchKind {
    PrimaryRequest,
    PrimaryOutput,
    DependencyRequest,
    DependencyOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowApi {
    pub api: String,
    pub group: Option<String>,
    pub sequences: BTreeSet<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowOwner {
    pub scope: String,
    pub group: Option<String>,
}

/// Find matchable events of business exchanges in a minute of Source time.
/// `after_sequence` only filters the legacy API summary.
pub fn dispatch_window(
    target_root: &Path,
    recording_root: &Path,
    failed_sequence: u64,
    after_sequence: u64,
) -> Result<DispatchWindow> {
    let catalog = ApiCatalog::load(&target_root.join(api_catalog::PATH))?.unwrap_or_default();
    let patterns = catalog.case_paths();
    let window = primary_dispatch_window(recording_root, failed_sequence, WINDOW_MICROS, 0)?;
    let mut apis = BTreeMap::new();
    let mut matches = BTreeMap::new();
    for (sequence, route) in window.requests {
        let path = matching_pattern(&patterns, &route.path);
        let owner = api_owner(&catalog, path);
        if sequence > after_sequence {
            let api = format!("{} {path}", route.method);
            let entry = apis.entry(api.clone()).or_insert_with(|| WindowApi {
                api,
                group: owner.group.clone(),
                sequences: BTreeSet::new(),
            });
            entry.sequences.insert(sequence);
        }
        matches.insert(
            sequence,
            WindowMatch {
                kind: WindowMatchKind::PrimaryRequest,
                exchange_sequence: sequence,
                owner: Some(owner),
            },
        );
    }
    for (sequence, (request, route)) in window.primary_outputs {
        matches.insert(
            sequence,
            WindowMatch {
                kind: WindowMatchKind::PrimaryOutput,
                exchange_sequence: request,
                owner: Some(api_owner(
                    &catalog,
                    matching_pattern(&patterns, &route.path),
                )),
            },
        );
    }
    for (sequence, source) in window.dependencies {
        matches.insert(
            sequence,
            WindowMatch {
                kind: WindowMatchKind::DependencyRequest,
                exchange_sequence: sequence,
                owner: source.map(|source| owner(&catalog, &patterns, source)),
            },
        );
    }
    for (sequence, (dependency, source)) in window.dependency_outputs {
        matches.insert(
            sequence,
            WindowMatch {
                kind: WindowMatchKind::DependencyOutput,
                exchange_sequence: dependency,
                owner: source.map(|source| owner(&catalog, &patterns, source)),
            },
        );
    }
    Ok(DispatchWindow {
        from_seq: failed_sequence,
        through_seq: window.through_sequence,
        apis: apis.into_values().collect(),
        matches,
        failure_owner: window
            .failure_owner
            .map(|source| owner(&catalog, &patterns, source)),
    })
}

fn matching_pattern<'a>(patterns: &'a [String], path: &'a str) -> &'a str {
    api_catalog::matching_case_pattern(patterns, path).unwrap_or(path)
}

fn api_owner(catalog: &ApiCatalog, pattern: &str) -> WindowOwner {
    WindowOwner {
        scope: format!("api:{pattern}"),
        group: catalog.routes().get(pattern).cloned(),
    }
}

fn owner(catalog: &ApiCatalog, patterns: &[String], source: WindowFailureOwner) -> WindowOwner {
    match source {
        WindowFailureOwner::Request(route) => {
            api_owner(catalog, matching_pattern(patterns, &route.path))
        }
        lifecycle => {
            let scope = match lifecycle {
                WindowFailureOwner::Startup => "startup",
                WindowFailureOwner::Shutdown => "shutdown",
                WindowFailureOwner::Request(_) => unreachable!(),
            };
            WindowOwner {
                scope: scope.into(),
                group: Some(scope.into()),
            }
        }
    }
}
