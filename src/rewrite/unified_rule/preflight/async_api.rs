//! Source entry conditions can be witnessed before their new lifecycle is recorded.
use super::*;

pub(super) fn verify(
    bundle: &mut Bundle,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    requires_recording: bool,
    result: &mut Preflight,
) -> Result<()> {
    if !selected.contains(crate::policy::ASYNC_API_ID) {
        return Ok(());
    }
    if requires_recording {
        result
            .obligations
            .insert(crate::config::native_policy::SourceObligation::FreshRecording);
        result
            .pending_effect_evidence
            .insert(crate::policy::ASYNC_API_ID.into());
    }
    if policy.async_api.is_empty() {
        return Ok(());
    }
    let mut observed = BTreeMap::<String, usize>::new();
    for directory in bundle.cases.clone().into_values() {
        let request = bundle.request(&directory.join("request.json"))?;
        let method = request["method"]
            .as_str()
            .context("async Source method unavailable")?;
        let uri = request["uri"]
            .as_str()
            .context("async Source URI unavailable")?;
        let body = capture(&request["body"])
            .ok()
            .and_then(|bytes| crate::json_value::parse(&bytes));
        for (api, rule) in &policy.async_api {
            if crate::policy::async_api_matches(api, rule, method, uri, body.as_ref()) {
                *observed.entry(api.clone()).or_default() += 1;
            }
        }
    }
    for api in policy.async_api.keys() {
        ensure!(
            observed.get(api).is_some_and(|count| *count > 0),
            "async API {api:?} has no complete Source request satisfying its condition"
        );
    }
    let count = observed.values().sum::<usize>();
    result.source_validations += count;
    result
        .rules
        .insert(crate::policy::ASYNC_API_ID.into(), count);
    Ok(())
}
