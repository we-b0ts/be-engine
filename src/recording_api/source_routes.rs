//! Confirmed HTTP Source registrations, separate from observed request paths.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::RecordingApi;
use crate::path_pattern::{matches_path_pattern, path_patterns_overlap};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub struct HttpSourceRoutes {
    routes: Vec<RecordingApi>,
    methods: BTreeMap<String, MethodRoutes>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MethodRoutes {
    exact: BTreeMap<String, usize>,
    patterns: Vec<usize>,
}

impl HttpSourceRoutes {
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = &RecordingApi> {
        self.routes.iter()
    }

    pub fn resolve(&self, method: &str, path: &str) -> Option<&RecordingApi> {
        let routes = self.methods.get(method)?;
        routes
            .exact
            .get(path)
            .copied()
            .or_else(|| {
                routes
                    .patterns
                    .iter()
                    .copied()
                    .find(|index| matches_path_pattern(self.routes[*index].path_pattern(), path))
            })
            .map(|index| &self.routes[index])
    }

    pub(crate) fn merged(&self, registrations: impl IntoIterator<Item = String>) -> Result<Self> {
        self.routes
            .iter()
            .map(ToString::to_string)
            .chain(registrations)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .try_into()
    }

    /// A confirmed static registration carves its exact path out of a pattern.
    pub(crate) fn permits_static_overlap(&self, method: &str, left: &str, right: &str) -> bool {
        let (literal, pattern) = match (left.contains('*'), right.contains('*')) {
            (false, true) => (left, right),
            (true, false) => (right, left),
            _ => return false,
        };
        self.methods
            .get(method)
            .is_some_and(|routes| routes.exact.contains_key(literal))
            && matches_path_pattern(pattern, literal)
    }

    pub(crate) fn selects(&self, method: &str, path: &str, selector: &str) -> bool {
        self.resolve(method, path)
            .is_some_and(|owner| owner.path_pattern() == selector)
    }
}

impl TryFrom<Vec<String>> for HttpSourceRoutes {
    type Error = anyhow::Error;

    fn try_from(values: Vec<String>) -> Result<Self> {
        ensure!(
            values.len() <= 100_000,
            "HTTP Source registration bound exceeded"
        );
        let mut seen = BTreeSet::new();
        let mut registry = Self::default();
        for value in values {
            let api: RecordingApi = value.parse()?;
            ensure!(
                api.method().as_str() != "MOTAN",
                "HTTP Source routes cannot register MOTAN"
            );
            ensure!(
                seen.insert(api.to_string()),
                "duplicate HTTP Source registration: {api}"
            );
            registry.routes.push(api);
        }
        registry.routes.sort_by_key(ToString::to_string);
        for (index, api) in registry.routes.iter().enumerate() {
            let method = registry
                .methods
                .entry(api.method().to_string())
                .or_default();
            if api.is_dynamic() {
                ensure!(
                    method.patterns.iter().all(|previous| {
                        !path_patterns_overlap(
                            registry.routes[*previous].path_pattern(),
                            api.path_pattern(),
                        )
                    }),
                    "ambiguous HTTP Source patterns for {}: {}",
                    api.method(),
                    api.path_pattern()
                );
                method.patterns.push(index);
            } else {
                method.exact.insert(api.path_pattern().to_owned(), index);
            }
        }
        Ok(registry)
    }
}

impl From<HttpSourceRoutes> for Vec<String> {
    fn from(registry: HttpSourceRoutes) -> Self {
        registry.routes.iter().map(ToString::to_string).collect()
    }
}

#[cfg(test)]
mod tests;
