use super::*;
pub use traffic_engine::replay::report::global_evidence::regular::*;
use traffic_engine::replay::report::global_evidence::regular_store::Identity;
use traffic_replay::report::{GlobalReportProjection, GlobalReportRuntime, ReportRows};
pub(super) fn prepare_regular<P: ReplayProtocolSet>(
    report: &Path,
    state: &RuntimeState<P>,
    protocol: &str,
) -> Result<Option<RegularEvidence>> {
    let Some(baseline) = state.regular_global.get(protocol) else {
        return Ok(None);
    };
    let mut extras = Vec::new();
    state.visit_global_report(protocol, ReportRows::Extras, &mut |row| {
        extras.push(row);
        Ok(())
    })?;
    RegularEvidence::from_live_snapshot(
        report,
        baseline,
        state.global_report_snapshot(protocol)?,
        extras,
    )
    .map(Some)
}
pub(crate) fn initialize<P: ReplayProtocolSet>(
    state: &mut RuntimeState<P>,
    report: &Path,
    policy: &str,
) -> Result<()> {
    ensure!(
        state.regular_global.is_empty(),
        "Global report baseline was already initialized"
    );
    let Some(source) = state.global_path.clone() else {
        return Ok(());
    };
    let (index, _) = crate::dependency_index::global::load_global_index_for_replay(
        &source,
        P::validate_source_record,
        &std::sync::atomic::AtomicBool::new(false),
        crate::protocols::default_providers().evidence(),
    )?;
    for protocol in state.global_report_protocols() {
        let protocol = protocol.as_str();
        let layout = state.global_report_layout(protocol)?;
        if !state.global_report_is_stable(protocol) {
            tracing::warn!(
                protocol,
                "Source transformations require a session-specific report projection"
            );
            continue;
        }
        let identity = Identity {
            source_sha256: if let Some(root) =
                crate::dependency_index::recording::root(&state.root_dir)
            {
                let (_, manifest) = crate::dependency_index::recording::manifest(&root)?;
                crate::policy_evidence::digest(&serde_json::to_vec(&(
                    manifest.files,
                    state.dependency_attribution_snapshot.as_ref(),
                ))?)
            } else {
                index.sha256.clone()
            },
            source_bytes: index.stamp.size,
            policy: policy.into(),
            protocol: protocol.into(),
            layout,
            semantics: state.global_report_semantics(protocol),
        };
        let baseline =
            RegularBaseline::retain_from_source(report, identity, Some(&source), |visitor| {
                state.visit_global_report(protocol, ReportRows::Core, visitor)
            })?;
        state.initialize_global_report(protocol, baseline.visible)?;
        state.regular_global.insert(protocol.into(), baseline);
    }
    Ok(())
}
