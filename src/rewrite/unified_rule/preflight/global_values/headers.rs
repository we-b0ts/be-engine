//! Global HTTP header observations retain their protected carrier envelope.
use super::*;
use crate::value_contract::http_headers::{self, HeaderSnapshot};

fn snapshot(value: &Value) -> Result<HeaderSnapshot> {
    if value.is_null() {
        Ok(HeaderSnapshot::new())
    } else {
        serde_json::from_value(value.clone()).context("invalid protected HTTP header snapshot")
    }
}

pub(super) fn dependency(
    source: &[u8],
    target: &[u8],
    surface: Surface,
    policy: &crate::policy::HttpPolicy,
    clocks: AnchorClocks,
) -> Result<(Comparison, Vec<u8>)> {
    let source: Value = serde_json::from_slice(source)?;
    let mut target: Value = serde_json::from_slice(target)?;
    let name = match surface {
        Surface::DependencyRequest => "request_headers",
        Surface::DependencyResponse => "response_headers",
        _ => anyhow::bail!("invalid HTTP dependency header surface"),
    };
    let before = snapshot(&source[name])?;
    let after = snapshot(&target[name])?;
    let comparison = http_headers::compare(&before, &after, policy, clocks)?;
    if comparison.passed() && !source[name].is_null() {
        target[name] = serde_json::to_value(http_headers::mask(&before, &after, policy)?)?;
    }
    Ok((comparison, serde_json::to_vec(&target)?))
}

pub(super) fn primary(
    bundle: &mut Bundle,
    case: &str,
    directory: &Path,
    request: &Value,
    policy: &crate::policy::HttpPolicy,
    result: &mut Preflight,
) -> Result<()> {
    let super::super::super::manifest::PrimaryResponse { source, target } =
        bundle.primary_response(case, directory)?;
    let pair = crate::replay::response_payload_pair(request, &source, None)?;
    let before = snapshot(&source["headers"])?;
    let clocks = AnchorClocks::for_response(
        crate::value_contract::time::ClockPair {
            source: pair.request_times.source,
            target: pair.request_times.source,
        },
        crate::value_contract::time::ClockPair {
            source: pair.times.source,
            target: pair.times.source,
        },
    );
    let checked = http_headers::compare(&before, &before, policy, clocks)?;
    let selected = BTreeSet::from([crate::policy::GLOBAL_HTTP_ID.into()]);
    if !record_source(&checked, &selected, result)? {
        return Ok(());
    }
    let Some(target) = target else {
        result.missing_target_witnesses += 1;
        return Ok(());
    };
    let Some(pair) = super::super::response::target_pair(request, &source, &target, case, result)?
    else {
        return Ok(());
    };
    let after = snapshot(&target["headers"])?;
    let checked = http_headers::compare(
        &before,
        &after,
        policy,
        AnchorClocks::for_response(pair.request_times, pair.times),
    )
    .and_then(|comparison| valid_count(&comparison, &selected));
    if checked.is_ok() {
        result.independent_target_validations += 1;
    } else {
        result.defer_target_comparison(case, Surface::ApiResponse, None);
    }
    Ok(())
}
