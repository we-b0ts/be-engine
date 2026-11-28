//! API coverage derived from the sealed route inventory and committed primary events.

use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use traffic_engine_config::config::api_catalog::{self, ApiCatalog};
use traffic_engine_e2e_contract::{E2eEventSessionApiProgress, E2eEventSessionCaseProgress};
use traffic_engine_evidence::session::SessionApiCounts;
use traffic_recording_store::session_summary::{self, SessionRouteSummary};
use uuid::Uuid;

pub(super) struct ApiProgress {
    by_route: HashMap<String, HashMap<String, usize>>,
    apis: Vec<(String, SessionApiCounts)>,
    in_flight: HashMap<Uuid, usize>,
    verified: usize,
    cases_completed: u64,
    cases_total: u64,
}

impl ApiProgress {
    pub(super) fn load(target_root: &Path, recording_root: &Path) -> Result<Self> {
        let patterns = ApiCatalog::load(&target_root.join(api_catalog::PATH))?
            .unwrap_or_default()
            .case_paths();
        let summary = session_summary::read(recording_root)?;
        Self::new(summary.routes, &patterns)
    }

    fn new(routes: Vec<SessionRouteSummary>, patterns: &[String]) -> Result<Self> {
        let mut by_route = HashMap::<_, HashMap<_, _>>::new();
        let mut by_label = HashMap::new();
        let mut apis = Vec::new();
        let mut cases_total = 0_u64;
        for route in routes {
            let selector =
                api_catalog::matching_case_pattern(patterns, &route.path).unwrap_or(&route.path);
            let label = format!("{} {selector}", route.method);
            let index = *by_label.entry(label.clone()).or_insert_with(|| {
                let index = apis.len();
                apis.push((label, SessionApiCounts::default()));
                index
            });
            ensure!(route.requests > 0, "recording route has no requests");
            cases_total = cases_total
                .checked_add(route.requests)
                .context("recorded primary exchange count exceeds u64")?;
            apis[index].1.recorded += route.requests;
            ensure!(
                by_route
                    .entry(route.method)
                    .or_default()
                    .insert(route.path, index)
                    .is_none(),
                "duplicate route in sealed recording summary"
            );
        }
        Ok(Self {
            by_route,
            apis,
            in_flight: HashMap::new(),
            verified: 0,
            cases_completed: 0,
            cases_total,
        })
    }

    pub(super) fn identify(&self, request: &Value) -> Result<Option<usize>> {
        if request["_session_probe"] == true {
            return Ok(None);
        }
        let method = request["method"]
            .as_str()
            .context("missing primary HTTP method")?;
        let uri: hyper::Uri = request["uri"]
            .as_str()
            .context("missing primary HTTP URI")?
            .parse()
            .context("invalid recorded primary HTTP URI")?;
        self.by_route
            .get(method)
            .and_then(|paths| paths.get(uri.path()))
            .copied()
            .map(Some)
            .context("recorded primary request route is missing from the sealed summary")
    }

    pub(super) fn start(&mut self, exchange: Uuid, api: Option<usize>) {
        if let Some(api) = api {
            self.in_flight.insert(exchange, api);
        }
    }

    pub(super) fn finish(&mut self, exchange: Uuid) -> Result<()> {
        if let Some(index) = self.in_flight.remove(&exchange) {
            let counts = &mut self.apis[index].1;
            ensure!(
                counts.verified < counts.recorded,
                "matched more primary exchanges than were recorded"
            );
            counts.verified += 1;
            self.cases_completed += 1;
            if counts.verified == counts.recorded {
                self.verified += 1;
            }
        }
        Ok(())
    }

    pub(super) fn status(&self) -> E2eEventSessionApiProgress {
        E2eEventSessionApiProgress {
            verified: self.verified,
            total: Some(self.apis.len()),
        }
    }

    pub(super) fn case_status(&self) -> E2eEventSessionCaseProgress {
        E2eEventSessionCaseProgress {
            completed: self.cases_completed,
            total: Some(self.cases_total),
        }
    }

    pub(super) fn into_counts(self) -> BTreeMap<String, SessionApiCounts> {
        self.apis.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn verifies_an_api_after_all_canonical_route_exchanges_finish() -> Result<()> {
        let routes = ["/api/items/1", "/api/items/2", "/api/items/current"]
            .into_iter()
            .enumerate()
            .map(|(index, path)| SessionRouteSummary {
                method: "GET".into(),
                path: path.into(),
                requests: 1,
                first_seq: index as u64 + 1,
            })
            .collect();
        let mut progress = ApiProgress::new(
            routes,
            &["/api/items/current".into(), "/api/items/*".into()],
        )?;
        assert_eq!(progress.status().total, Some(2));
        assert_eq!(progress.case_status().total, Some(3));
        assert_eq!(progress.case_status().completed, 0);
        let probe = Uuid::new_v4();
        let probe_id = progress
            .identify(&json!({"method":"GET", "uri":"/api/ready", "_session_probe":true}))?;
        progress.start(probe, probe_id);
        progress.finish(probe)?;
        assert_eq!(progress.status().verified, 0);
        assert_eq!(progress.case_status().completed, 0);

        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let current = Uuid::new_v4();
        for (id, uri) in [
            (first, "/api/items/1?view=summary"),
            (second, "/api/items/2"),
            (current, "/api/items/current"),
        ] {
            let api = progress.identify(&json!({"method":"GET", "uri":uri}))?;
            progress.start(id, api);
        }
        progress.finish(second)?;
        assert_eq!(progress.status().verified, 0);
        assert_eq!(progress.case_status().completed, 1);
        progress.finish(second)?;
        assert_eq!(progress.case_status().completed, 1);
        progress.finish(first)?;
        assert_eq!(progress.status().verified, 1);
        assert_eq!(progress.case_status().completed, 2);
        let counts = progress.into_counts();
        assert_eq!(counts["GET /api/items/*"].recorded, 2);
        assert_eq!(counts["GET /api/items/*"].verified, 2);
        assert_eq!(counts["GET /api/items/current"].verified, 0);
        Ok(())
    }
}
