//! Compact API dispatch evidence for a failed Source event.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use traffic_engine_config::config::api_catalog::{self, ApiCatalog};
use traffic_recording_store::session::{PrimaryRoute, WindowFailureOwner, primary_dispatch_window};

const WINDOW_MICROS: u64 = 60_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchWindow {
    pub from_seq: u64,
    pub through_seq: u64,
    pub apis: Vec<WindowApi>,
    pub failure_owner: Option<WindowOwner>,
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

/// Find recorded primary requests in the minute starting at the failed event.
pub fn dispatch_window(
    target_root: &Path,
    recording_root: &Path,
    failed_sequence: u64,
    after_sequence: u64,
) -> Result<DispatchWindow> {
    let catalog = ApiCatalog::load(&target_root.join(api_catalog::PATH))?.unwrap_or_default();
    let patterns = catalog.case_paths();
    let window = primary_dispatch_window(
        recording_root,
        failed_sequence,
        WINDOW_MICROS,
        after_sequence,
    )?;
    let mut apis = BTreeMap::new();
    for (sequence, route) in window.requests {
        let (api, group) = label(&catalog, &patterns, route);
        let entry = apis.entry(api.clone()).or_insert_with(|| WindowApi {
            api,
            group,
            sequences: BTreeSet::new(),
        });
        entry.sequences.insert(sequence);
    }
    Ok(DispatchWindow {
        from_seq: failed_sequence,
        through_seq: window.through_sequence,
        apis: apis.into_values().collect(),
        failure_owner: window
            .failure_owner
            .map(|source| owner(&catalog, &patterns, source)),
    })
}

fn label(
    catalog: &ApiCatalog,
    patterns: &[String],
    route: PrimaryRoute,
) -> (String, Option<String>) {
    let path = api_catalog::matching_case_pattern(patterns, &route.path).unwrap_or(&route.path);
    let api = format!("{} {path}", route.method);
    (api, catalog.routes().get(path).cloned())
}

fn owner(catalog: &ApiCatalog, patterns: &[String], source: WindowFailureOwner) -> WindowOwner {
    match source {
        WindowFailureOwner::Request(route) => {
            let (api, group) = label(catalog, patterns, route);
            WindowOwner {
                scope: format!("api:{api}"),
                group,
            }
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
