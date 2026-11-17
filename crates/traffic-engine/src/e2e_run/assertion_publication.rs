//! Retarget staged assertion evidence and keep every detail fingerprint consistent.
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};

use super::{
    model::{ActiveRunState, AssertionReport, ResponseAssertionSummary},
    store,
};

#[cfg(test)]
mod tests;

pub(super) fn prepare(
    state: &ActiveRunState,
    old: &Path,
    staging: &Path,
    published: &Path,
) -> Result<ActiveRunState> {
    let staged = super::replay_publication::prepare(state, old, staging, published)?;
    let state = &staged;
    let mut reports = BTreeMap::new();
    for path in std::iter::once(state.assertions_report.clone()).chain(
        state
            .apis
            .iter()
            .map(|api| api.report_dir.join("assertions.json")),
    ) {
        let physical = staged_path(&path, old, staging)?;
        match fs::read(&physical) {
            Ok(bytes) => {
                let report: AssertionReport = serde_json::from_slice(&bytes)
                    .with_context(|| format!("invalid assertion report {}", physical.display()))?;
                reports.insert(physical, report);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("failed to read staged assertion report"),
        }
    }
    let mut details = BTreeMap::new();
    for summary in state
        .cases
        .iter()
        .filter_map(|case| case.response_assertion.as_ref())
        .chain(reports.values().flat_map(|report| {
            report
                .cases
                .iter()
                .filter_map(|case| case.response.as_ref())
        }))
    {
        if details.contains_key(&summary.detail_report) {
            continue;
        }
        let physical = staged_path(&summary.detail_report, old, staging)?;
        let mut detail: serde_json::Value =
            serde_json::from_slice(&fs::read(&physical).with_context(|| {
                format!("failed to read assertion detail {}", physical.display())
            })?)?;
        ensure!(detail.is_object(), "assertion detail must be an object");
        for field in [
            "request_path",
            "expected_response_path",
            "actual_response_path",
            "policy_path",
        ] {
            if let Some(value) = detail.get_mut(field)
                && let Some(raw) = value.as_str()
                && let Ok(relative) = Path::new(raw).strip_prefix(old)
            {
                *value = serde_json::Value::String(
                    published.join(relative).to_string_lossy().into_owned(),
                );
            }
        }
        store::write_json(&physical, &detail)?;
        details.insert(
            summary.detail_report.clone(),
            crate::verification_progress::fingerprint(&fs::read(physical)?),
        );
    }
    let mut output = store::state_for_published_directory(state, old, published)?;
    for (case, original) in output.cases.iter_mut().zip(&state.cases) {
        if let (Some(summary), Some(original)) =
            (&mut case.response_assertion, &original.response_assertion)
        {
            summary.detail_fingerprint = details[&original.detail_report].clone();
        }
    }
    for (path, mut report) in reports {
        for summary in report
            .cases
            .iter_mut()
            .filter_map(|case| case.response.as_mut())
        {
            retarget_summary(summary, old, published, &details)?;
        }
        store::write_json(&path, &report)?;
    }
    Ok(output)
}

fn staged_path(path: &Path, old: &Path, staging: &Path) -> Result<PathBuf> {
    Ok(staging.join(path.strip_prefix(old).with_context(|| {
        format!(
            "assertion evidence escaped its run directory: {}",
            path.display()
        )
    })?))
}

fn retarget_summary(
    summary: &mut ResponseAssertionSummary,
    old: &Path,
    published: &Path,
    details: &BTreeMap<PathBuf, String>,
) -> Result<()> {
    summary.detail_fingerprint = details
        .get(&summary.detail_report)
        .context("assertion detail fingerprint was not prepared")?
        .clone();
    for path in [
        &mut summary.detail_report,
        &mut summary.request,
        &mut summary.expected_response,
        &mut summary.actual_response,
    ] {
        if let Ok(relative) = path.strip_prefix(old) {
            *path = published.join(relative);
        }
    }
    Ok(())
}
