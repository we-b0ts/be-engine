use super::*;
use crate::dependency_index::PageWriter;
pub use traffic_engine_replay::replay::report::global_evidence::*;
use traffic_replay::report::GlobalReportProjection;
mod projection;
pub(crate) mod regular;
pub(crate) async fn prepare<P: ReplayProtocolSet>(
    state: Arc<Mutex<RuntimeState<P>>>,
    report_path: &Path,
) -> Result<GlobalDetails> {
    let report_path = report_path.to_owned();
    tokio::task::spawn_blocking(move || {
        let state = state.blocking_lock();
        ensure!(
            state.finalized_at.is_some(),
            "Global detail publication requires finalized Replay state"
        );
        let mut manifests = serde_json::Map::new();
        let root = report_path
            .parent()
            .context("Global report has no parent directory")?;
        let mut pages = Vec::new();
        for protocol in state.global_report_protocols() {
            let protocol = protocol.as_str();
            state.global_report_layout(protocol)?;
            if let Some(regular) = regular::prepare_regular(&report_path, &state, protocol)? {
                let extensions = state
                    .protocols
                    .global_report_extensions(protocol, &report_path)?;
                manifests.insert(
                    protocol.into(),
                    serde_json::to_value(ProtocolEvidence::new(protocol, regular, extensions))?,
                );
                continue;
            }
            let mut writer = PageWriter::<Value>::new_in(&root.join("global-dependencies"))?;
            let mut visit = |item| writer.push(item);
            if state.native.owns_global_report(protocol) {
                state.native.visit_global_unused(protocol, &mut visit)?;
            } else {
                P::visit_global_unused(&state, protocol, &mut visit)?;
            }
            let inventory = writer.finish()?;
            let manifest = inventory.manifest().relative_to(root)?;
            let value = state
                .protocols
                .global_report_fallback(protocol, &report_path, manifest)?;
            manifests.insert(protocol.into(), value);
            pages.push(inventory);
        }
        Ok(GlobalDetails {
            manifests: Value::Object(manifests),
            pages,
        })
    })
    .await
    .context("Global dependency detail publication failed")?
}

pub use traffic_engine_replay::replay::report::global_evidence::preparation;
use traffic_engine_replay::replay::report::global_evidence::protocol::ProtocolEvidence;

#[cfg(test)]
mod preparation_tests;
