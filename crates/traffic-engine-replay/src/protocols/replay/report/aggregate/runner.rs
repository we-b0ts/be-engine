//! Aggregate one runner-selected session, including shared method evidence.
use super::*;
use anyhow::ensure;

pub fn aggregate_runner_replay_report(
    case_source: &Path,
    report_path: &Path,
    snapshot_root: &Path,
    options: &ReplayAggregateOptions,
) -> Result<ReplayAggregateReport> {
    aggregate_runner_report(case_source, report_path, snapshot_root, options, None)
}

/// Aggregate the caller's loaded report with exactly the same confinement,
/// session membership and immutable recording checks as the file entry point.
#[cfg(test)]
pub fn aggregate_runner_replay_report_value(
    case_source: &Path,
    report_path: &Path,
    snapshot_root: &Path,
    report: &Value,
    options: &ReplayAggregateOptions,
) -> Result<ReplayAggregateReport> {
    aggregate_runner_report(
        case_source,
        report_path,
        snapshot_root,
        options,
        Some(report),
    )
}

fn aggregate_runner_report(
    case_source: &Path,
    report_path: &Path,
    snapshot_root: &Path,
    options: &ReplayAggregateOptions,
    report: Option<&Value>,
) -> Result<ReplayAggregateReport> {
    let case_source = canonical_dir(case_source, "case source")?;
    let report_path = canonical_file(report_path, "replay report")?;
    if !report_path.starts_with(&case_source) {
        let snapshot_root = canonical_dir(snapshot_root, "runner snapshot")?;
        ensure_within(&report_path, &snapshot_root, "runner replay report")?;
    }
    ensure!(
        options.session_ids.len() == 1 && !options.case_ids.is_empty(),
        "runner aggregation requires one replay session and selected case ids"
    );
    let loaded;
    let report = match report {
        Some(report) => report,
        None => {
            loaded = serde_json::from_slice::<Value>(&fs::read(&report_path)?)
                .with_context(|| format!("invalid replay report JSON {}", report_path.display()))?;
            &loaded
        }
    };
    let session_case_ids = required_array(report, "cases", &report_path)?
        .iter()
        .map(|case| required_string(case, "case_id", &report_path).map(ToOwned::to_owned))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        options.case_ids.is_subset(&session_case_ids),
        "runner replay report does not cover every selected API case"
    );
    // A focused method retains the entire route session. Validate all session
    // cases against the recording and preserve session-wide dependency gates.
    aggregate_report_values(
        case_source,
        std::iter::once(Ok((report_path, report))),
        &ReplayAggregateOptions {
            case_ids: session_case_ids,
            session_ids: options.session_ids.clone(),
        },
    )
}
