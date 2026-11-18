//! Assert independently observed semantic messages and complete connection closure.
use crate::value_contract::json::Comparison;
use anyhow::Result;
use serde_json::Value;
#[cfg(test)]
mod client_ack;
#[cfg(test)]
mod contracts;
#[cfg(test)]
mod socketio;
use traffic_protocol_http::interaction::verification;
pub(super) use verification::AckContext;
pub use verification::sse::decode_sse;

use super::model::ResponseAssertionCaseReport;

pub(super) fn decrypt_output_bytes(
    bytes: &[u8],
    path: &std::path::Path,
) -> Result<Option<Vec<u8>>> {
    let mut response: Value = serde_json::from_slice(bytes)?;
    if crate::interaction::private::decrypt_output(&mut response, path)? {
        return Ok(Some(serde_json::to_vec(&response)?));
    }
    Ok(None)
}

pub(super) use verification::validate_input;

use crate::interaction::model::{EndReason, OutputObservation, Protocol};
#[cfg(test)]
use crate::interaction::model::{TRANSCRIPT_VERSION, WireMessage};

#[allow(clippy::too_many_arguments)]
pub(super) fn compare(
    expected: Option<&OutputObservation>,
    actual: Option<&OutputObservation>,
    global: Option<&crate::policy::CompiledJsonPolicy>,
    times: super::RequestTimes,
    request_times: super::RequestTimes,
    copies: &crate::value_contract::time_copies::DeliveredTimeCopies,
    report: &mut ResponseAssertionCaseReport,
    ack_context: Option<&AckContext>,
    source_heartbeat_tail: bool,
    max_message_bytes: usize,
) -> Result<()> {
    report.fast_heartbeat_tail_skipped = actual.is_some_and(|actual| {
        actual.protocol == Protocol::SocketIo
            && actual.end.reason == EndReason::FastHeartbeatTailSkipped
    });
    let checked = compare_outputs_global_with_time_copies(
        expected,
        actual,
        global,
        times,
        request_times,
        copies,
        ack_context,
        source_heartbeat_tail,
        max_message_bytes,
    )?;
    report.identity_pairs.extend(checked.identity_pairs());
    report.applied_body_rule_ids.extend(checked.evaluated);
    report.differences.extend(
        checked
            .differences
            .into_iter()
            .map(super::unified::contract_difference),
    );
    Ok(())
}

/// One adapter serves Source preflight, independent Target proof and Replay.
pub fn compare_outputs_global(
    expected: Option<&OutputObservation>,
    actual: Option<&OutputObservation>,
    global: Option<&crate::policy::CompiledJsonPolicy>,
    times: super::RequestTimes,
    request_times: super::RequestTimes,
    max_message_bytes: usize,
) -> Result<Comparison> {
    compare_outputs_global_with_time_copies(
        expected,
        actual,
        global,
        times,
        request_times,
        &Default::default(),
        None,
        false,
        max_message_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn compare_outputs_global_with_time_copies(
    expected: Option<&OutputObservation>,
    actual: Option<&OutputObservation>,
    global: Option<&crate::policy::CompiledJsonPolicy>,
    times: super::RequestTimes,
    request_times: super::RequestTimes,
    copies: &crate::value_contract::time_copies::DeliveredTimeCopies,
    ack_context: Option<&AckContext>,
    source_heartbeat_tail: bool,
    max_message_bytes: usize,
) -> Result<Comparison> {
    let adapter = global.map(|plan| ValueAdapter { plan, copies });
    verification::compare_outputs(
        expected,
        actual,
        adapter
            .as_ref()
            .map(|adapter| adapter as &dyn verification::ValueComparator),
        &verification::ComparisonContext {
            times,
            request_times,
            ack_context,
            source_heartbeat_tail,
            max_message_bytes,
        },
    )
}

struct ValueAdapter<'a> {
    plan: &'a crate::policy::CompiledJsonPolicy,
    copies: &'a crate::value_contract::time_copies::DeliveredTimeCopies,
}

impl verification::ValueComparator for ValueAdapter<'_> {
    fn compare(
        &self,
        source: &[u8],
        target: &[u8],
        clocks: crate::value_contract::json::AnchorClocks,
    ) -> Result<Comparison> {
        crate::value_contract::global::compare(source, target, self.plan, &[], clocks)
    }

    fn compare_sse_data(
        &self,
        source: &[u8],
        target: &[u8],
        clocks: crate::value_contract::json::AnchorClocks,
    ) -> Result<Comparison> {
        use crate::value_codec::CodecView;
        if crate::json_value::parse(source).is_none() {
            return self.compare(source, target, clocks);
        }
        let source = CodecView::decode(&crate::policy::Codec::Json, source)?;
        let target = CodecView::decode(&crate::policy::Codec::Json, target)?;
        let proofs =
            self.copies
                .proofs(&source.logical, self.plan, clocks, clocks.observation())?;
        crate::value_contract::global::compare_decoded_with_time_copies(
            &source,
            &target,
            self.plan,
            &[],
            clocks,
            &proofs,
        )
    }
}
