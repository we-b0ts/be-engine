//! Optional per-route HTTP method metadata finalized with a recording.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result};
use serde::Deserialize;

pub type ApiMethods = BTreeMap<String, Vec<String>>;

pub fn from_observed(apis: &BTreeSet<String>) -> ApiMethods {
    let mut routes = BTreeMap::<String, BTreeSet<String>>::new();
    for api in apis {
        if let Some((method, route)) = api.split_once(' ')
            && route.starts_with('/')
            && method != "MOTAN"
        {
            routes
                .entry(route.into())
                .or_default()
                .insert(method.into());
        }
    }
    routes
        .into_iter()
        .map(|(route, methods)| (route, methods.into_iter().collect()))
        .collect()
}

pub fn load(case_source: &Path) -> Result<ApiMethods> {
    #[derive(Deserialize)]
    struct Manifest {
        #[serde(default)]
        api_methods: Option<ApiMethods>,
    }
    let path = case_source.join("recording-run.json");
    let payload = match fs::read(&path) {
        Ok(payload) => payload,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(ApiMethods::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let manifest: Manifest = serde_json::from_slice(&payload)
        .with_context(|| format!("failed to parse recorded API methods in {}", path.display()))?;
    Ok(manifest.api_methods.unwrap_or_default())
}

pub fn for_route(index: &ApiMethods, route: &str) -> Vec<String> {
    if !route.contains('*') {
        return index.get(route).cloned().unwrap_or_default();
    }
    // A rewrite can canonicalize concrete recorded routes into a path pattern
    // after capture. Merge only the already persisted metadata for its members.
    index
        .iter()
        .filter(|(recorded, _)| {
            *recorded == route || crate::path_pattern::matches_path_pattern(route, recorded)
        })
        .flat_map(|(_, methods)| methods.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_per_route_and_merges_canonicalized_recording_members() {
        let index = from_observed(&BTreeSet::from([
            "GET /users/1".into(),
            "OPTIONS /users/1".into(),
            "POST /users/2".into(),
            "DELETE /projects".into(),
            "GET /configured/*".into(),
            "HEAD /configured/*".into(),
            "MOTAN /rpc".into(),
        ]));
        assert_eq!(for_route(&index, "/users/1"), ["GET", "OPTIONS"]);
        assert_eq!(for_route(&index, "/users/*"), ["GET", "OPTIONS", "POST"]);
        assert_eq!(for_route(&index, "/projects"), ["DELETE"]);
        assert_eq!(for_route(&index, "/configured/*"), ["GET", "HEAD"]);
        assert!(for_route(&index, "/missing").is_empty());
        assert!(!index.contains_key("/rpc"));
    }

    #[test]
    fn historical_recordings_remain_empty_and_are_never_backfilled() {
        let root = tempfile::tempdir().unwrap();
        assert!(load(root.path()).unwrap().is_empty());
        let manifest = root.path().join("recording-run.json");
        let original = br#"{"status":"completed","observed_api_count":2}"#;
        fs::write(&manifest, original).unwrap();
        // Even available case methods must not be rescanned for a legacy recording.
        fs::write(
            root.path().join("request.json"),
            r#"{"method":"POST","uri":"/api"}"#,
        )
        .unwrap();
        assert!(load(root.path()).unwrap().is_empty());
        assert_eq!(fs::read(&manifest).unwrap(), original);
    }
}
