use super::*;
use crate::http::rewrite::{RewriteInput, matches};
use crate::policy::{Codec, Surface};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::borrow::Cow;

pub(super) fn validate(
    scope: &NativeSourceScope<'_>,
    rule: &n::NativeRule,
    files: &[PathBuf],
    artifacts: &mut BTreeSet<PathBuf>,
) -> Result<usize> {
    match &rule.effect {
        n::NativeEffect::CaptureHttp(effect) => {
            ensure!(
                effect.source_revision == scope.source_revision,
                "capture scope Source revision differs from the current immutable snapshot"
            );
            ensure!(
                crate::source_snapshot::source_image_revision(scope.target_root)?
                    == scope.source_revision,
                "Source snapshot changed before capture planning"
            );
            let mut matched = 0;
            for file in files.iter().filter(|file| {
                file.file_name()
                    .is_some_and(|name| name == crate::dependency_index::scoped::CASE_SCOPE)
            }) {
                let request: Value =
                    serde_json::from_slice(&std::fs::read(file.with_file_name("request.json"))?)?;
                let uri = request["uri"]
                    .as_str()
                    .context("Source request URI missing")?
                    .parse::<hyper::Uri>()?;
                if effect
                    .case_paths
                    .iter()
                    .any(|path| crate::path_pattern::matches_path_pattern(path, uri.path()))
                {
                    matched += 1;
                }
            }
            ensure!(
                matched > 0,
                "capture scope has no observed Source API path; recording is required before proving this selector"
            );
            Ok(matched)
        }
        n::NativeEffect::CaptureBreeze(effect) => {
            let path = if effect.snapshot_dir.is_absolute() {
                effect.snapshot_dir.clone()
            } else {
                scope.target_root.join(&effect.snapshot_dir)
            };
            let snapshot = crate::breeze::snapshot::Snapshot::load(&path)?;
            // The owner resolves the full descriptor inventory, so freeze every
            // descriptor rather than only today's selected filename.
            artifacts.extend(
                snapshot
                    .resources()
                    .iter()
                    .map(|resource| resource.descriptor_path.clone()),
            );
            for resource in &effect.resources {
                snapshot.resolve(resource)?;
            }
            Ok(effect.resources.len())
        }
        n::NativeEffect::CaptureHttpResponse(effect) => {
            let projected = super::super::capture_response(rule, effect);
            let transformation = match &effect.contract {
                n::CaptureResponseContract::Policy(definition) => {
                    Some(traffic_extensions::policies().prepare_transform_definition(definition)?)
                }
                n::CaptureResponseContract::Documents { rules } => {
                    let configuration = serde_json::from_value(serde_json::json!({"rules":rules}))?;
                    Some(
                        traffic_extensions::policies()
                            .prepare_transform("documents", &configuration)?,
                    )
                }
                _ => None,
            };
            let mut pointers = std::collections::BTreeMap::<String, usize>::new();
            if let n::CaptureResponseContract::Urls { pointers: selected } = &effect.contract {
                pointers.extend(
                    selected
                        .iter()
                        .map(|selected| (selected.contract.clone(), 0)),
                );
            }
            let mut count = 0;
            each_event(
                files,
                |_, event| Ok(matching_headers(&projected, event)?.is_some()),
                |path, _, event| {
                    let Some(headers) = matching_headers(&projected, event)? else {
                        return Ok(());
                    };
                    let envelope = crate::protocols::replay::http_source_witness(
                        event,
                        Surface::DependencyResponse,
                        path,
                    )?;
                    let body = crate::protocols::replay::http_witness_value(
                        &envelope,
                        Surface::DependencyResponse,
                    )?
                    .context("capture response has no complete body slot")?;
                    let decoded = original_body(event, &headers, &body)?;
                    if let Some(transformation) = &transformation {
                        let uri: hyper::Uri = event["uri"]
                            .as_str()
                            .context("capture response has no request URI")?
                            .parse()?;
                        let context =
                            serde_json::from_value(serde_json::json!({"query":uri.query()}))?;
                        if transformation
                            .inspect(&traffic_policy::TransformInput {
                                bytes: &decoded,
                                context: &context,
                            })?
                            .is_some()
                        {
                            count += 1;
                        }
                        return Ok(());
                    }
                    let logical =
                        crate::value_codec::CodecView::decode(&Codec::Json, &decoded)?.logical;
                    for (pointer, seen) in &mut pointers {
                        let Some(value) = logical.pointer(pointer).filter(|value| !value.is_null())
                        else {
                            continue;
                        };
                        let text = value
                            .as_str()
                            .context("captured Source URL field is not a string")?;
                        if crate::http::rewrite::inspect_url_target(text)?.is_some() {
                            *seen += 1;
                        }
                    }
                    count += 1;
                    Ok(())
                },
            )?;
            ensure!(
                count > 0 && pointers.values().all(|count| *count > 0),
                "capture response requires complete matching Source responses for every selected URL field"
            );
            Ok(count)
        }
        _ => anyhow::bail!("Source capture owner received another effect"),
    }
}

fn original_body<'a>(
    event: &Value,
    headers: &hyper::HeaderMap,
    body: &'a [u8],
) -> Result<Cow<'a, [u8]>> {
    let original = event["capture"]["transformations"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|receipt| receipt["surface"] == "http_response");
    if let Some(receipt) = original {
        let receipt: traffic_model::recording::Transformation =
            serde_json::from_value(receipt.clone())?;
        let original = STANDARD.decode(&receipt.original_body_base64)?;
        ensure!(
            original.len() <= crate::value_limits::MAX_VALUE_BYTES,
            "original response rewrite body exceeds its budget"
        );
        ensure!(
            format!("{:x}", Sha256::digest(&original)) == receipt.original_sha256
                && format!("{:x}", Sha256::digest(body)) == receipt.delivered_sha256,
            "response rewrite provenance does not match its original and delivered bodies"
        );
        Ok(Cow::Owned(original))
    } else {
        crate::http::rewrite::decode_rewrite_body(
            headers,
            body,
            crate::value_limits::MAX_VALUE_BYTES,
        )
    }
}

fn matching_headers(
    rule: &crate::config::HttpResponseRewriteRuleConfig,
    event: &Value,
) -> Result<Option<hyper::HeaderMap>> {
    if event["event_type"] != "http_exchange" {
        return Ok(None);
    }
    let method = event["method"]
        .as_str()
        .context("Source HTTP method missing")?
        .parse::<hyper::Method>()?;
    let uri = event["uri"]
        .as_str()
        .context("Source HTTP URI missing")?
        .parse::<hyper::Uri>()?;
    let Some(status) = event["response_status"]
        .as_u64()
        .and_then(|status| u16::try_from(status).ok())
    else {
        return Ok(None);
    };
    let mut headers = hyper::HeaderMap::new();
    let snapshot: std::collections::BTreeMap<String, Vec<String>> =
        serde_json::from_value(event["response_headers"].clone())?;
    for (name, values) in snapshot {
        let name = name.parse::<hyper::header::HeaderName>()?;
        for value in values {
            headers.append(name.clone(), value.parse()?);
        }
    }
    let input = RewriteInput {
        method: &method,
        uri: &uri,
        authority: event["authority"]
            .as_str()
            .or_else(|| uri.authority().map(|value| value.as_str())),
        status: hyper::StatusCode::from_u16(status)?,
        headers: &headers,
        body: &[],
    };
    if !matches(rule, &input) {
        return Ok(None);
    }
    Ok(Some(headers))
}
