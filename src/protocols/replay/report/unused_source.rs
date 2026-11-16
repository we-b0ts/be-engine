//! MySQL Source identities supplement the shared native occurrence projection.
use super::*;
use crate::replay::report::unused_source::{SourceIdentity, SourceRow};
use serde_json::Value;
use traffic_replay::ReplaySource;

pub(in crate::protocols::replay) fn rows(
    state: &RuntimeState<ReplayProtocols>,
    report: &Value,
) -> Vec<SourceRow> {
    report["unused_case_exchanges"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(position, row)| {
            let case = row["case_id"].as_str()?;
            let index = usize::try_from(row["index"].as_u64()?).ok()?;
            let exchange = state.protocol_data().mysql.exchanges.get(index)?;
            if exchange.source != ReplaySource::Case || exchange.case_id.as_deref() != Some(case) {
                return None;
            }
            Some(SourceRow {
                pointer: format!("/unused_case_exchanges/{position}"),
                case: case.into(),
                exchange_id: exchange.record.capture.as_ref()?.exchange_id,
                identity: SourceIdentity::EventType("mysql_exchange"),
            })
        })
        .collect()
}
