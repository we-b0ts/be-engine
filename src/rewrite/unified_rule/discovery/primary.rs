//! Authenticated primary-response discovery, independently scheduled from dependencies.
use super::*;

pub(super) fn observe(
    drafts: &mut Drafts,
    assertions: &Path,
    api: &str,
    schemas: Option<&CompiledPolicy>,
) -> Result<()> {
    let assertions: Value = serde_json::from_slice(&fs::read(assertions)?)?;
    for case in assertions["cases"].as_array().into_iter().flatten() {
        if drafts.observations >= OBSERVATION_LIMIT {
            drafts.limited = true;
            break;
        }
        drafts.observations += 1;
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
            drafts.limited = true;
            continue;
        }
        let mut expected_value: Value = serde_json::from_slice(&fs::read(expected)?)?;
        if crate::interaction::private::decrypt_output(&mut expected_value, Path::new(expected))
            .is_err()
        {
            drafts.limited = true;
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
            drafts.limited = true;
            continue;
        };
        let mut request_value: Value = serde_json::from_slice(&fs::read(request)?)?;
        if crate::interaction::private::decrypt_request(&mut request_value, Path::new(request))
            .is_err()
        {
            drafts.limited = true;
            continue;
        }
        let request = request_value;
        let expected = expected_value;
        let Ok(mut source_pair) = crate::replay::response_payload_pair(&request, &expected, None)
        else {
            continue;
        };
        if let Some(pair) = actual.as_ref().and_then(|actual| {
            crate::replay::response_payload_pair(&request, &expected, Some(actual)).ok()
        }) {
            source_pair = pair;
        }
        if !source_pair.body_available {
            interaction::observe(
                drafts,
                &source_pair,
                api,
                case["case_id"].as_str().unwrap_or("api-response"),
                schemas,
            )?;
            continue;
        }
        let source = source_pair.source;
        let target = actual
            .as_ref()
            .and_then(|actual| {
                crate::replay::response_payload_pair(&request, &expected, Some(actual)).ok()
            })
            .and_then(|pair| pair.target);
        let base = json!({"surface":"api.response","match":{"api":api},"slot":"body"});
        let clocks = AnchorClocks {
            case: crate::value_contract::time::ClockPair {
                source: request["timestamp"].as_str().and_then(|s| s.parse().ok()),
                target: actual
                    .as_ref()
                    .and_then(|value| value["request_sent_at"].as_str())
                    .and_then(|s| s.parse().ok()),
            },
            ..Default::default()
        };
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
    Ok(())
}
