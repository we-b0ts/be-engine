//! Authenticated primary-response discovery, independently scheduled from dependencies.
use super::*;

pub(super) fn observe(
    drafts: &mut Drafts,
    assertions: &Path,
    state: &RewriteState,
    schemas: Option<&CompiledPolicy>,
    cursor: &mut Cursor,
) -> Result<bool> {
    let assertions: Value = serde_json::from_slice(&fs::read(assertions)?)?;
    let representative = state
        .active_issue
        .as_ref()
        .and_then(|issue| issue.representative.as_ref())
        .map(|case| case.case_id.as_str());
    let mut cases = assertions["cases"]
        .as_array()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    cases.sort_by_key(|case| {
        if case["case_id"].as_str() == representative && representative.is_some() {
            0
        } else if case["response"]["passed"] == false || case["response"]["status"] == "failed" {
            1
        } else {
            2
        }
    });
    for (case_index, case) in cases.into_iter().enumerate().skip(cursor.primary_case) {
        if drafts.observations >= OBSERVATION_LIMIT {
            drafts.limited = true;
            return Ok(false);
        }
        drafts.observations += 1;
        let event_offset = cursor.primary_event;
        cursor.primary_case = case_index + 1;
        cursor.primary_event = 0;
        let summary = &case["response"];
        let (Some(expected), Some(request)) = (
            summary["expected_response"].as_str(),
            summary["request"].as_str(),
        ) else {
            continue;
        };
        let actual = summary["actual_response"].as_str();
        if [Some(expected), actual, Some(request)]
            .into_iter()
            .flatten()
            .any(|path| fs::metadata(path).map_or(true, |m| m.len() > 4 * 1024 * 1024))
        {
            drafts.limit("primary_payload_bytes");
            continue;
        }
        let mut expected_value: Value = serde_json::from_slice(&fs::read(expected)?)?;
        if crate::interaction::private::decrypt_output(&mut expected_value, Path::new(expected))
            .is_err()
        {
            drafts.limit("private_primary_evidence");
            continue;
        }
        let actual: Result<Option<Value>> = actual
            .map(|path| -> Result<Value> {
                let mut value = serde_json::from_slice(&fs::read(path)?)?;
                crate::interaction::private::decrypt_output(&mut value, Path::new(path))?;
                Ok(value)
            })
            .transpose();
        let Ok(actual) = actual else {
            drafts.limit("private_primary_evidence");
            continue;
        };
        let mut request_value: Value = serde_json::from_slice(&fs::read(request)?)?;
        if crate::interaction::private::decrypt_request(&mut request_value, Path::new(request))
            .is_err()
        {
            drafts.limit("private_primary_evidence");
            continue;
        }
        let request = request_value;
        let expected = expected_value;
        let Ok(mut source_pair) =
            crate::primary_protocol::assertion::response_payload_pair(&request, &expected, None)
        else {
            continue;
        };
        if let Some(pair) = actual.as_ref().and_then(|actual| {
            crate::primary_protocol::assertion::response_payload_pair(
                &request,
                &expected,
                Some(actual),
            )
            .ok()
        }) {
            source_pair = pair;
        }
        drafts.headers(
            &expected["headers"],
            actual.as_ref().map(|actual| &actual["headers"]),
            case["case_id"].as_str().unwrap_or("api-response"),
            AnchorClocks::for_response(source_pair.request_times, source_pair.times),
        )?;
        if !source_pair.body_available {
            if let Some(next_event) = interaction::observe(
                drafts,
                &source_pair,
                &state.api,
                case["case_id"].as_str().unwrap_or("api-response"),
                schemas,
                event_offset,
            )? {
                cursor.primary_case = case_index;
                cursor.primary_event = next_event;
                return Ok(false);
            }
            continue;
        }
        let clocks = AnchorClocks::for_response(source_pair.request_times, source_pair.times);
        let source = source_pair.source;
        let target = source_pair.target;
        let base = json!({"surface":"api.response","match":{"api":state.api},"slot":"body"});
        drafts.observe(
            &source,
            target.as_deref(),
            base,
            case["case_id"].as_str().unwrap_or("api-response"),
            clocks,
            schemas,
            None,
        )?;
    }
    Ok(true)
}
