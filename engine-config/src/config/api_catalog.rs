//! Git-managed canonical API routes and their regression groups.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, ensure};

use crate::recording_api::RecordingApiScope;

pub const PATH: &str = ".traffic-e2e/apis.yaml";
pub const FILE_NAME: &str = "apis.yaml";
pub const TEMPLATE: &str = "{}\n";
const MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct ApiCatalog {
    routes: BTreeMap<String, String>,
    empty_groups: BTreeSet<String>,
}

impl ApiCatalog {
    pub fn read(path: &Path) -> Result<Option<String>> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
        };
        ensure!(
            metadata.is_file(),
            "{} must be a regular file",
            path.display()
        );
        ensure!(
            metadata.len() <= MAX_BYTES,
            "{} exceeds the catalog size limit",
            path.display()
        );
        let yaml = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        ensure!(
            yaml.len() as u64 <= MAX_BYTES,
            "{} exceeds the catalog size limit",
            path.display()
        );
        Ok(Some(yaml))
    }

    pub fn load(path: &Path) -> Result<Option<Self>> {
        Self::read(path)?
            .map(|yaml| Self::parse(&yaml).with_context(|| format!("load {}", path.display())))
            .transpose()
    }

    pub fn parse(yaml: &str) -> Result<Self> {
        // Mapping rejects duplicate group keys before conversion to the typed document.
        let mapping: serde_yaml::Mapping = serde_yaml::from_str(yaml)?;
        let groups: BTreeMap<String, Option<Vec<String>>> =
            serde_yaml::from_value(serde_yaml::Value::Mapping(mapping))?;
        let mut routes = BTreeMap::new();
        let mut empty_groups = BTreeSet::new();
        for (group, apis) in groups {
            validate_group(&group)?;
            let apis = apis.unwrap_or_default();
            if apis.is_empty() {
                empty_groups.insert(group.clone());
            }
            for api in apis {
                ensure!(
                    routes.insert(api.clone(), group.clone()).is_none(),
                    "API {api:?} occurs more than once in {FILE_NAME}"
                );
            }
        }
        Self {
            routes: BTreeMap::new(),
            empty_groups,
        }
        .with_routes(routes)
    }

    pub fn with_routes(mut self, routes: BTreeMap<String, String>) -> Result<Self> {
        for (api, group) in &routes {
            validate_route(api)?;
            validate_group(group)?;
        }
        self.routes = routes;
        Ok(self)
    }

    pub fn routes(&self) -> &BTreeMap<String, String> {
        &self.routes
    }

    pub fn encode(&self) -> Result<String> {
        let mut groups = self
            .empty_groups
            .iter()
            .map(|group| (group.as_str(), Vec::<&str>::new()))
            .collect::<BTreeMap<_, _>>();
        for (api, group) in &self.routes {
            groups.entry(group).or_default().push(api);
        }
        Ok(serde_yaml::to_string(&groups)?)
    }

    /// An explicit static route takes precedence over a wildcard. Retain the
    /// existing lexical precedence between wildcard patterns.
    pub fn case_paths(&self) -> Vec<String> {
        let (mut exact, wildcards): (Vec<_>, Vec<_>) = self
            .routes
            .keys()
            .filter(|route| route.starts_with('/'))
            .cloned()
            .partition(|route| !route.contains('*'));
        exact.extend(wildcards);
        exact
    }
}

pub fn validate_group(group: &str) -> Result<()> {
    ensure!(
        !group.is_empty()
            && group.len() <= 128
            && group
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
        "group id must contain 1..=128 ASCII letters, digits, '.', '_' or '-'"
    );
    Ok(())
}

pub fn matching_case_pattern<'a>(patterns: &'a [String], path: &str) -> Option<&'a str> {
    patterns
        .iter()
        .find(|pattern| crate::path_pattern::matches_path_pattern(pattern, path))
        .map(String::as_str)
}

pub fn validate_route(route: &str) -> Result<()> {
    let parsed = route.parse::<RecordingApiScope>()?;
    ensure!(
        parsed.to_string() == route,
        "use canonical route identity {parsed:?}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_round_trip_in_stable_order_and_supply_case_paths() {
        let catalog =
            ApiCatalog::parse("items: [/items/*, /items/current]\nhealth: [/ready]\nnext:\n")
                .unwrap();
        let yaml = catalog.encode().unwrap();
        assert_eq!(
            yaml,
            "health:\n- /ready\nitems:\n- /items/*\n- /items/current\nnext: []\n"
        );
        assert_eq!(
            catalog.case_paths(),
            ["/items/current", "/ready", "/items/*"]
        );
        assert_eq!(ApiCatalog::parse(&yaml).unwrap().encode().unwrap(), yaml);
    }

    #[test]
    fn rejects_duplicate_groups_and_routes_and_invalid_selectors() {
        for yaml in [
            "items: [/items]\nitems: [/other]",
            "items: [/items]\nother: [/items]",
            "items: [/items, /items]",
            "bad group: [/items]",
            "items: [GET /items]",
            "items: [/items*]",
        ] {
            assert!(ApiCatalog::parse(yaml).is_err(), "{yaml}");
        }
    }
}
