//! Complete API implementation review for one sealed recording.

use super::*;
use traffic_e2e::{
    config::api_catalog::{self, ApiCatalog},
    event_work::ApiConfirmation,
    path_pattern::matches_path_pattern,
    session,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ApiReview {
    pub confirmations: Vec<ApiConfirmation>,
    pub tasks: BTreeMap<String, ApiTask>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ApiTask {
    pub finding: Finding,
    pub apis: Vec<ApiConfirmation>,
}

impl ApiReview {
    pub fn load(
        target: &Path,
        recording: &Path,
        confirmations: Vec<ApiConfirmation>,
        reviewed_findings: &[&Finding],
        used_causes: &BTreeSet<&str>,
    ) -> Result<Self> {
        let mut submitted = BTreeMap::new();
        for row in confirmations {
            let label = row.api.clone();
            ensure!(
                submitted.insert(label.clone(), row).is_none(),
                "duplicate API confirmation {label}"
            );
        }
        let mut tasks = BTreeMap::<_, ApiTask>::new();
        let mut confirmations = Vec::new();
        let catalog = ApiCatalog::load(&target.join(api_catalog::PATH))?.unwrap_or_default();
        let mut routes = catalog.routes().clone();
        let inventory = session::recorded_apis(target, recording)?;
        let missing: Vec<_> = inventory
            .iter()
            .filter(|api| !submitted.contains_key(&api.api))
            .map(|api| api.api.as_str())
            .collect();
        ensure!(
            missing.is_empty(),
            "confirm the remaining recorded APIs: {}",
            missing.join(", ")
        );
        for api in &inventory {
            let mut row = submitted.remove(&api.api).expect("confirmed above");
            let uncatalogued = api.case_pattern.is_none();
            let pattern = if let Some(pattern) = &api.case_pattern {
                ensure!(
                    row.case_pattern
                        .as_ref()
                        .is_none_or(|value| value == pattern),
                    "use the existing case_pattern for {}",
                    api.api
                );
                pattern.clone()
            } else {
                row.case_pattern
                    .clone()
                    .with_context(|| format!("{} needs a case_pattern", api.api))?
            };
            let group = if let Some(group) = &api.group {
                ensure!(
                    row.group.as_ref().is_none_or(|value| value == group),
                    "use the existing group for {}",
                    api.api
                );
                group.clone()
            } else {
                row.group
                    .clone()
                    .with_context(|| format!("{} needs a group", api.api))?
            };
            api_catalog::validate_group(&group)?;
            api_catalog::validate_route(&pattern)?;
            ensure!(
                pattern.starts_with('/')
                    && api
                        .paths
                        .iter()
                        .all(|path| matches_path_pattern(&pattern, path)),
                "case_pattern {pattern} must match the recorded paths for {}",
                api.api
            );
            if let Some(previous) = routes.insert(pattern.clone(), group.clone()) {
                ensure!(
                    previous == group,
                    "conflicting groups for case_pattern {pattern}"
                );
            }
            row.case_pattern = Some(pattern.clone());
            row.group = Some(group.clone());
            let scope = format!("api:{} {pattern}", api.method);
            let related = |finding: &&Finding| {
                finding.scope.as_deref().is_some_and(|value| {
                    value == scope
                        || value.strip_prefix("api:").is_some_and(|label| {
                            label == api.api
                                || label
                                    .strip_prefix(&api.method)
                                    .and_then(|suffix| suffix.strip_prefix(' '))
                                    .is_some_and(|path| {
                                        api.paths.iter().any(|recorded| recorded == path)
                                    })
                        })
                })
            };
            let mut related = reviewed_findings.iter().copied().filter(related);
            let prior = related.next();
            for finding in prior.into_iter().chain(related) {
                ensure!(
                    finding.group.as_deref().is_none_or(|value| value == group),
                    "finding {} must use API group {group}",
                    finding.root_cause
                );
            }
            if !row.implemented || uncatalogued {
                let cause = prior.map_or_else(
                    || api_cause(&scope, used_causes),
                    |finding| finding.root_cause.clone(),
                );
                let entry = tasks.entry(cause.clone()).or_insert_with(|| ApiTask {
                    finding: Finding {
                        root_cause: cause,
                        summary: if row.implemented {
                            format!("Register the case pattern and group for {}.", api.api)
                        } else {
                            format!("Implement {} in the Target.", api.api)
                        },
                        sequences: BTreeSet::new(),
                        scope: Some(scope),
                        group: Some(group),
                    },
                    apis: Vec::new(),
                });
                entry.finding.sequences.insert(api.first_seq);
                entry.apis.push(row.clone());
            }
            confirmations.push(row);
        }
        ensure!(
            submitted.is_empty(),
            "unknown recorded APIs: {}",
            submitted.into_keys().collect::<Vec<_>>().join(", ")
        );
        let patterns = catalog.with_routes(routes)?.case_paths();
        for (api, row) in inventory.iter().zip(&confirmations) {
            ensure!(
                api.paths
                    .iter()
                    .all(|path| api_catalog::matching_case_pattern(&patterns, path)
                        == row.case_pattern.as_deref()),
                "case patterns change the selected pattern for {}",
                api.api
            );
        }
        Ok(Self {
            confirmations,
            tasks,
        })
    }

    pub fn check_resubmission(&self, rows: Vec<ApiConfirmation>) -> Result<()> {
        let mut rows = rows;
        rows.sort_by(|left, right| left.api.cmp(&right.api));
        ensure!(
            rows.len() == self.confirmations.len()
                && rows.iter().zip(&self.confirmations).all(|(row, prior)| {
                    row.api == prior.api
                        && row.implemented == prior.implemented
                        && row
                            .case_pattern
                            .as_ref()
                            .is_none_or(|pattern| Some(pattern) == prior.case_pattern.as_ref())
                        && row
                            .group
                            .as_ref()
                            .is_none_or(|group| Some(group) == prior.group.as_ref())
                }),
            "API confirmations are already recorded for this recording"
        );
        Ok(())
    }

    pub fn validate_candidate<'a>(
        &self,
        root: &Path,
        causes: impl Iterator<Item = &'a str>,
    ) -> Result<()> {
        let mut apis = causes
            .filter_map(|cause| self.tasks.get(cause))
            .flat_map(|task| &task.apis)
            .peekable();
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
            let pattern = api.case_pattern.as_deref().expect("reviewed API pattern");
            ensure!(
                catalog.routes().get(pattern) == api.group.as_ref(),
                "candidate must register {pattern} in group {} in {}",
                api.group.as_deref().unwrap_or_default(),
                api_catalog::PATH
            );
        }
        Ok(())
    }
}

fn api_cause(scope: &str, used_causes: &BTreeSet<&str>) -> String {
    let base = format!("API review for {scope}");
    if !used_causes.contains(base.as_str()) {
        return base;
    }
    (2..)
        .map(|suffix| format!("{base} ({suffix})"))
        .find(|candidate| !used_causes.contains(candidate.as_str()))
        .expect("finite set of used finding identities")
}
