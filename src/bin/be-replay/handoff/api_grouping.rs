//! Source route grouping and publication of the managed API catalog.

use std::{collections::BTreeMap, path::Path, process::Command};

use anyhow::{Context, Result, ensure};
use traffic_e2e::{
    config::{
        api_catalog::{self, ApiCatalog},
        edit,
    },
    event_work::{ApiConfirmation, ApiGrouping},
    path_pattern::matches_path_pattern,
    session::RecordedApi,
};

pub(crate) struct CatalogUpdate {
    original: Option<String>,
    yaml: String,
}

impl CatalogUpdate {
    pub fn prepare(target: &Path, inventory: &[RecordedApi], rows: &[ApiGrouping]) -> Result<Self> {
        let original = ApiCatalog::read(&target.join(api_catalog::PATH))?;
        let catalog = original
            .as_deref()
            .map(ApiCatalog::parse)
            .transpose()?
            .unwrap_or_default();
        let mut routes = catalog.routes().clone();
        let mut submitted = BTreeMap::new();
        for row in rows {
            let api = row.api.as_str();
            ensure!(
                submitted.insert(api, row).is_none(),
                "duplicate API grouping {api}"
            );
        }
        ensure!(!submitted.is_empty(), "supply the ungrouped recorded APIs");
        for api in inventory.iter().filter(|api| api.case_pattern.is_none()) {
            let row = submitted
                .get(api.api.as_str())
                .with_context(|| format!("{} needs a case_pattern and group", api.api))?;
            api_catalog::validate_group(&row.group)?;
            api_catalog::validate_route(&row.case_pattern)?;
            ensure!(
                row.case_pattern.starts_with('/')
                    && api
                        .paths
                        .iter()
                        .all(|path| matches_path_pattern(&row.case_pattern, path)),
                "case pattern {} must match the recorded paths for {}",
                row.case_pattern,
                api.api
            );
            if let Some(previous) = routes.insert(row.case_pattern.clone(), row.group.clone()) {
                ensure!(
                    previous == row.group,
                    "conflicting groups for {}",
                    row.case_pattern
                );
            }
        }
        let revised = catalog.with_routes(routes)?;
        let patterns = revised.case_paths();
        for api in inventory {
            let pattern = api.case_pattern.as_deref().unwrap_or_else(|| {
                &submitted
                    .remove(api.api.as_str())
                    .expect("validated grouping")
                    .case_pattern
            });
            ensure!(
                api.paths.iter().all(|path| {
                    api_catalog::matching_case_pattern(&patterns, path) == Some(pattern)
                }),
                "case patterns change the selected pattern for {}",
                api.api
            );
        }
        ensure!(
            submitted.is_empty(),
            "submit only ungrouped recorded APIs: {}",
            submitted.into_keys().collect::<Vec<_>>().join(", ")
        );
        Ok(Self {
            original,
            yaml: revised.encode()?,
        })
    }

    pub fn publish(self, target: &Path) -> Result<()> {
        let path = target.join(api_catalog::PATH);
        ensure!(
            ApiCatalog::read(&path)? == self.original,
            "{} changed while planning API groups",
            path.display()
        );
        if self.original.is_some() {
            edit::write_atomic(&path, self.yaml.as_bytes())
        } else {
            edit::create_atomic(&path, self.yaml.as_bytes())
        }
    }
}

pub(super) fn validate_committed_catalog<'a>(
    root: &Path,
    apis: impl Iterator<Item = &'a ApiConfirmation>,
) -> Result<()> {
    let mut apis = apis.peekable();
    if apis.peek().is_none() {
        return Ok(());
    }
    let catalog = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["show", &format!("HEAD:./{}", api_catalog::PATH)])
        .output()
        .context("read API catalog from candidate")?;
    ensure!(
        catalog.status.success(),
        "candidate must commit {}",
        api_catalog::PATH
    );
    let catalog = ApiCatalog::parse(std::str::from_utf8(&catalog.stdout)?)?;
    for api in apis {
        let pattern = api.case_pattern.as_deref().expect("grouped API pattern");
        ensure!(
            catalog.routes().get(pattern) == api.group.as_ref(),
            "candidate must register {pattern} in group {} in {}",
            api.group.as_deref().unwrap_or_default(),
            api_catalog::PATH
        );
    }
    Ok(())
}
