//! Source entry conditions can be witnessed before their new lifecycle is recorded.
use super::*;

pub fn verify(
    state: &RewriteState,
    bundle: &mut Bundle,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    _capture_changed: bool,
    result: &mut Preflight,
) -> Result<()> {
    if !selected.contains(crate::policy::ASYNC_API_ID) {
        return Ok(());
    }
    if policy.async_api.is_empty() {
        return Ok(());
    }
    let mut observed = BTreeMap::<String, usize>::new();
    let (recording, manifest) = crate::dependency_index::recording::manifest(
        state
            .case_source
            .as_deref()
            .context("async rule requires sealed Source inventory")?,
    )?;
    let mut directories = bundle.cases.values().cloned().collect::<BTreeSet<_>>();
    directories.extend(
        manifest
            .inputs
            .into_iter()
            .filter(|input| input.complete)
            .map(|input| recording.join(input.path)),
    );
    for directory in directories {
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
        let response_path = directory.join("expected-response.json");
        bundle.freeze(&response_path)?;
        let response: Value = serde_json::from_slice(&fs::read(&response_path)?)?;
        let response_body = capture(&response["body"])
            .ok()
            .and_then(|bytes| crate::json_value::parse(&bytes));
        for (api, rules) in &policy.async_api {
            if rules.iter().any(|rule| {
                crate::policy::async_api_matches(api, rule, method, uri, body.as_ref())
                    && crate::policy::async_response_matches(rule, response_body.as_ref())
            }) {
                *observed.entry(api.clone()).or_default() += 1;
                let scope = crate::recorder::async_api::AsyncScope::for_primary(
                    &policy.async_api,
                    &method.parse()?,
                    &uri.parse()?,
                    &body
                        .as_ref()
                        .map(serde_json::to_vec)
                        .transpose()?
                        .unwrap_or_default(),
                )
                .context("matching async Source scenario unavailable")?;
                scope.select_response(response_body.as_ref());
                let path = bundle.dependency_path(&directory)?;
                bundle.freeze(&path)?;
                let bytes = crate::dependency_index::scoped::read_bytes(&path)?;
                let mut completed = false;
                for line in bytes
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
                {
                    let event: Value = serde_json::from_slice(line)?;
                    completed |= scope.observe_recorded(&event)?.is_some_and(|signal| {
                        signal.end_reason == crate::recorder::async_api::AsyncEndReason::Resource
                    });
                }
                if !completed {
                    let potential = crate::recorder::async_api::AsyncScope::for_primary(
                        &policy.async_api,
                        &method.parse()?,
                        &uri.parse()?,
                        &body
                            .as_ref()
                            .map(serde_json::to_vec)
                            .transpose()?
                            .unwrap_or_default(),
                    )
                    .context("async investigation scope absent")?;
                    potential.select_response(response_body.as_ref());
                    let central = recording.join("dependencies.jsonl");
                    bundle.freeze(&central)?;
                    let mut elsewhere = false;
                    crate::dependency_index::proof::visit(
                        &central,
                        |event| {
                            Ok(matches!(
                                event["event_type"].as_str(),
                                Some("mysql_exchange" | "redis_exchange" | "http_exchange")
                            ))
                        },
                        |event| {
                            elsewhere |= potential.observe_recorded(event)?.is_some_and(|signal| {
                                signal.end_reason
                                    == crate::recorder::async_api::AsyncEndReason::Resource
                            });
                            Ok(())
                        },
                    )?;
                    if elsewhere {
                        result.obligations.insert(
                            crate::config::native_policy::SourceObligation::AttributionReview,
                        );
                        result
                            .pending_effect_evidence
                            .insert(format!("async-attribution:{api}"));
                    } else {
                        result.capture_scopes.insert(api.clone(),"Source inventory does not contain the declared successful asynchronous completion resource".into());
                    }
                }
            }
        }
    }
    for api in policy.async_api.keys() {
        if !observed.get(api).is_some_and(|count| *count > 0) {
            result.capture_scopes.insert(
                api.clone(),
                "Source has no complete input/response selecting this asynchronous scenario".into(),
            );
        }
    }
    let count = observed.values().sum::<usize>();
    result.source_validations += count;
    result
        .rules
        .insert(crate::policy::ASYNC_API_ID.into(), count);
    Ok(())
}
