//! Render a captured async prefix without certifying an unobserved response EOF.
use super::*;

pub(super) fn materialize(
    owner: &crate::replay::policy::request_contract::RequestContracts,
    exchange: &mut ReplayHttpExchange,
    active_case: Option<&str>,
    request_started_at: chrono::DateTime<Utc>,
) -> Result<DependencyRuleDecision> {
    anyhow::ensure!(
        exchange.record.cleanup_authorized && exchange.record.native.response_stream.is_some(),
        "HTTP prefix rendering requires an exact authenticated async cleanup reference"
    );
    let mut decision = DependencyRuleDecision::default();
    let Some(case) = exchange.case_id.as_deref().or(active_case) else {
        return Ok(decision);
    };
    let payload = decode_body(
        exchange
            .record
            .native
            .response_body
            .as_ref()
            .context("HTTP cleanup prefix payload missing")?,
    )?;
    let delivered_at = Utc::now();
    let clocks = owner.contract_clocks(
        Some(case),
        request_headers::time_reference::source(&exchange.record),
        Some(request_started_at),
        exchange.record.native.timestamp,
        Some(delivered_at),
    );
    let value = materialize_value(owner, case, &payload, clocks, delivered_at, &mut decision)?;
    if value != payload {
        anyhow::ensure!(
            !witness::has_integrity_headers(exchange.record.native.response_headers.as_ref()),
            "HTTP prefix rebase requires a typed owner for its payload digest or signature headers"
        );
        stream::remap_prefix(
            exchange
                .record
                .native
                .response_stream
                .as_mut()
                .expect("validated prefix"),
            &payload,
            &value,
        )?;
    }
    let mut native_headers = response_headers_for_payload(
        exchange.record.native.response_headers.as_ref(),
        value.len(),
        delivered_at,
    );
    let expected_native_headers = request_headers::capture(&native_headers);
    if let Some(validation) = headers::materialize(
        owner,
        case,
        exchange.record.native.response_headers.as_ref(),
        &mut native_headers,
        clocks,
        delivered_at,
    )? {
        decision.value_contracts.push(validation);
    }
    anyhow::ensure!(
        expected_native_headers == request_headers::capture(&native_headers)
            || !witness::has_integrity_headers(exchange.record.native.response_headers.as_ref()),
        "HTTP prefix header rebase requires a typed owner for its digest or signature headers"
    );
    exchange.record.native.response_body = Some(RecordedBodyCapture {
        encoding: "base64".into(),
        truncated: false,
        stored_len: Some(value.len()),
        data: STANDARD.encode(value),
    });
    exchange.record.native.response_headers = Some(request_headers::capture(&native_headers));
    // This is a derived prefix delivery, never an independent complete-response
    // witness. Keep Source outcome, error, incomplete flag and absent EOF intact.
    Ok(decision)
}
