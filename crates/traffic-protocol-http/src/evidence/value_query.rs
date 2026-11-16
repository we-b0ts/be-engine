//! Select business payloads from authenticated native HTTP witness envelopes.
use anyhow::Result;
use serde_json::Value;
use traffic_protocol::evidence::{ValueEvidence, ValueQuery, ValueReader};

pub(super) fn query(
    _event: &Value,
    payload: &[u8],
    query: ValueQuery<'_>,
    reader: &dyn ValueReader,
) -> Result<ValueEvidence> {
    let documents = crate::witness::witness_value(payload, query.side)?
        .into_iter()
        .collect::<Vec<_>>();
    Ok(ValueEvidence::select(&documents, query, reader))
}
