use super::*;
use crate::policy::Surface;
use crate::replay::policy::{HttpPolicyContext, dynamic_values::HttpInput};

pub(super) fn validate(
    runtime: &mut ReplayPolicyRuntime,
    case: &NativeSourceCase<'_>,
    event: &Value,
    coverage: &mut super::coverage::Coverage,
) -> Result<()> {
    let relevant = runtime
        .request_contracts
        .compiled_rules()
        .is_some_and(|compiled| {
            compiled.native.iter().any(|rule| {
                matches!(
                    rule.rule.effect,
                    NativeEffect::HttpRequest(_)
                        | NativeEffect::Identity(_)
                        | NativeEffect::HttpClientMetadata(_)
                ) && (rule
                    .rule
                    .selector
                    .resource
                    .as_ref()
                    .is_some_and(|resource| resource.protocol == crate::policy::Protocol::Http)
                    || NativeScopeGuard::from_rule(&rule.rule)
                        .references
                        .iter()
                        .any(|resource| resource.protocol == crate::policy::Protocol::Http))
            })
        });
    if !relevant {
        return Ok(());
    }
    let raw = crate::replay::http_source_witness(event, Surface::DependencyRequest, case.dir)?;
    let envelope: Value = serde_json::from_slice(&raw)?;
    let target = crate::replay::TargetKey {
        host: envelope["endpoint"]["host"]
            .as_str()
            .context("Source HTTP host missing")?
            .into(),
        port: u16::try_from(
            envelope["endpoint"]["port"]
                .as_u64()
                .context("Source HTTP port missing")?,
        )?,
    };
    let method = envelope["method"]
        .as_str()
        .context("Source HTTP method missing")?;
    let uri = envelope["uri"]
        .as_str()
        .context("Source HTTP URI missing")?;
    let body = crate::replay::http_witness_value(&raw, Surface::DependencyRequest)?
        .context("Source HTTP request body missing")?;
    let source_time = started(event)?;
    if let Some(prepared) = runtime.request_contracts.prepare_http_body(
        case.id,
        &target,
        method,
        &super::super::super::pattern::uri_path(uri),
        &body,
        &body,
        crate::replay::assertion::RequestTimes {
            source: source_time,
            target: source_time,
        },
    ) {
        let prepared = prepared?;
        ensure!(
            prepared.source == prepared.actual,
            "Source HTTP field comparison changed values"
        );
        runtime.request_contracts.commit(prepared.decision);
    }
    coverage.references(
        runtime
            .dynamic_values
            .source_http_references(case.id, &target, method, uri, &body)?,
    );
    if let Some(normalized) = runtime.dynamic_values.http(
        Some(case.id),
        &target,
        method,
        HttpInput {
            uri,
            body: &body,
            request_started_at: source_time,
        },
        HttpInput {
            uri,
            body: &body,
            request_started_at: source_time,
        },
    ) {
        let normalized = normalized?;
        ensure!(
            normalized.source_body == normalized.actual_body
                && normalized.source_uri == normalized.actual_uri.to_string(),
            "Source HTTP identity self validation changed fields"
        );
        runtime.dynamic_values.commit(case.id, normalized.decision);
    }
    let context = HttpPolicyContext {
        request_times: crate::replay::assertion::RequestTimes {
            source: source_time,
            target: source_time,
        },
        case_id: Some(case.id),
        target: &target,
        method,
        recorded_uri: uri,
        actual_uri: uri,
    };
    let now = source_time
        .or_else(|| {
            case.request["timestamp"]
                .as_str()
                .and_then(|value| value.parse().ok())
        })
        .context("Source HTTP request clock missing")?;
    let mut decision = runtime
        .preview_http(&context, now)
        .map_err(anyhow::Error::msg)?;
    let headers: std::collections::BTreeMap<String, Vec<String>> =
        if envelope["request_headers"].is_null() {
            BTreeMap::new()
        } else {
            serde_json::from_value(envelope["request_headers"].clone())?
        };
    if let Some(result) = runtime.request_contracts.preview_multipart(
        case.id,
        &target,
        method,
        &super::super::super::pattern::uri_path(uri),
        &body,
        &headers,
        &body,
        &headers,
    ) {
        decision.value_contracts.push(result?);
    }
    let mut timestamps = Vec::new();
    for (name, (id, format)) in runtime.http_header_timestamp_rules(&context) {
        crate::replay::http::request_headers::timestamp::validate(
            format,
            headers.get(&name).map(Vec::as_slice),
            headers.get(&name).map(Vec::as_slice),
            crate::replay::assertion::RequestTimes {
                source: source_time,
                target: source_time,
            },
        )
        .map_err(anyhow::Error::msg)?;
        timestamps.push(id);
    }
    runtime.commit(Some(case.id), decision);
    runtime.commit_http_header_timestamps(&timestamps);
    let observed = runtime
        .http_client_metadata_headers(&context)
        .into_iter()
        .filter(|(name, _)| {
            headers.iter().any(|(key, values)| {
                key.eq_ignore_ascii_case(name)
                    && !values.is_empty()
                    && values
                        .iter()
                        .all(|value| !value.is_empty() && value != "<redacted>")
            })
        })
        .collect::<BTreeMap<_, _>>();
    for (name, id) in &observed {
        coverage.header(id, name);
    }
    runtime.commit_http_client_metadata(&observed);
    Ok(())
}
