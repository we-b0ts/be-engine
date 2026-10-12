//! Aggregate one runner-selected session, including shared method evidence.
use super::*;
use anyhow::ensure;

pub(crate) fn aggregate_runner_replay_report(
    case_source: &Path,
    report_path: &Path,
    snapshot_root: &Path,
    options: &ReplayAggregateOptions,
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
    let report: Value = serde_json::from_slice(&fs::read(&report_path)?)
        .with_context(|| format!("invalid replay report JSON {}", report_path.display()))?;
    let session_case_ids = required_array(&report, "cases", &report_path)?
        .iter()
        .map(|case| required_string(case, "case_id", &report_path).map(ToOwned::to_owned))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        options.case_ids.is_subset(&session_case_ids),
        "runner replay report does not cover every selected API case"
    );
    // A focused method retains the entire route session. Validate all session
    // cases against the recording and preserve session-wide dependency gates.
    aggregate_canonical_reports(
        case_source,
        vec![report_path],
        &ReplayAggregateOptions {
            case_ids: session_case_ids,
            session_ids: options.session_ids.clone(),
        },
    )
}
