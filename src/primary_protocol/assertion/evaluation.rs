//! Evaluate one primary response using native envelopes and content contracts.
use super::*;

pub(super) fn evaluate_response(
    inputs: AssertionInputs,
    loaded: &LoadedReplayPolicy,
) -> Result<ResponseAssertionCaseReport> {
    let AssertionInputs {
        body_available,
        times,
        request_times,
        case_id,
        request,
        request_path,
        expected_request_headers,
        actual_request_headers,
        expected_status,
        expected_headers,
        expected_sse_observation,
        expected_body,
        expected_path,
        expected_fingerprint,
        actual_status,
        actual_headers,
        actual_sse_observation,
        actual_body,
        actual_path,
        actual_fingerprint,
    } = inputs;
    let clocks = crate::value_contract::json::AnchorClocks::for_response(request_times, times);
    ensure!(
        loaded.document.version >= 3,
        "runner-owned response assertions require replay policy version 3"
    );
    let path = uri_path(&request.uri);
    let source_request_body = request
        .body
        .as_ref()
        .map(|body| decode_body(body, "immutable Source request"))
        .transpose()?
        .and_then(|body| crate::json_value::parse(&body));
    let native_selected = loaded
        .compiled
        .as_ref()
        .map(|compiled| {
            native::selected(
                compiled,
                &request.method,
                &path,
                source_request_body.as_ref(),
            )
            .into_iter()
            .filter(|rule| body_available || !rule.rule.effect.is_response_body())
            .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let native_root = if native::needs_startup(&native_selected) {
        crate::config::resolve_unified_policy_root(&loaded.path)?
    } else {
        PathBuf::from(".")
    };
    let native_context = loaded
        .compiled
        .as_ref()
        .map(|_| {
            native::NativeResponseContext::from_rules(
                &native_selected,
                &native_root,
                request_path.parent().unwrap_or(Path::new(".")),
            )
        })
        .transpose();
    let (native_context, native_key_unavailable) = match native_context {
        Ok(context) => (context, false),
        Err(_)
            if native_selected.iter().any(|rule| {
                matches!(
                    rule.rule.effect,
                    crate::policy::NativeEffect::ResponseJwt(_)
                )
            }) =>
        {
            (None, true)
        }
        Err(error) => return Err(error),
    };
    let native_body_ids = native_selected.iter().filter(|rule|
        matches!(&rule.rule.effect, crate::policy::NativeEffect::ResponseBody(effect) if effect.codec != crate::policy::native::BodyCodec::Json))
        .map(|rule| rule.rule.id.clone()).collect::<Vec<_>>();
    let native_headers = loaded
        .compiled
        .as_ref()
        .map(|_| {
            let rules = native_selected.iter().copied().cloned().collect::<Vec<_>>();
            crate::policy::runtime::native_projection::project_native(&rules)
        })
        .transpose()?;
    let response_rules = native_headers
        .as_ref()
        .map_or(&loaded.document.response_rules, |projection| {
            &projection.document.response_rules
        });
    let response_fields = response_rules.matching_replay_fields(&request.method, &path);
    let body_rules = response_rules.matching_response_body_rules(&request.method, &path);
    let body_rules = if loaded.compiled.is_some() {
        native::body::merge_opaque(body_rules)?
    } else {
        body_rules
    };
    ensure!(
        body_rules.len() <= 1,
        "multiple response-body rules match {} {}",
        request.method,
        path
    );
    let gateway_protocol = request.gateway_protocol()?;
    let mut report = ResponseAssertionCaseReport::new(
        case_id,
        request.method.clone(),
        path,
        gateway_protocol,
        request_path.display().to_string(),
        loaded.path.display().to_string(),
        loaded.fingerprint.clone(),
        expected_path.display().to_string(),
        expected_fingerprint,
        actual_path.display().to_string(),
        actual_fingerprint,
    );
    if native_key_unavailable {
        let mut difference = ResponseDifference::body_value_mismatch();
        difference.kind = ResponseDifferenceKind::JwtSigningKeyUnavailable;
        report.differences.push(difference);
    }
    if expected_status != actual_status {
        report
            .differences
            .push(ResponseDifference::status(expected_status, actual_status));
    }
    if gateway_protocol == ResponseGatewayProtocol::Http {
        sse::compare(
            expected_sse_observation,
            actual_sse_observation,
            &mut report,
        );
        headers::compare_with_rules(
            expected_headers.as_ref(),
            actual_headers.as_ref(),
            expected_request_headers.as_ref(),
            actual_request_headers.as_ref(),
            native_headers
                .as_ref()
                .map_or(&loaded.document.response_rules.headers, |projection| {
                    &projection.document.response_rules.headers
                }),
            loaded
                .compiled
                .as_ref()
                .and_then(|compiled| compiled.http.as_ref()),
            clocks,
            &mut report,
        )?;
    }
    if let Some(projection) = &native_headers {
        for id in report
            .applied_header_rule_ids
            .iter_mut()
            .chain(&mut report.unused_applicable_header_rule_ids)
        {
            if let Some(native_id) = projection.response_aliases.get(id) {
                *id = native_id.clone();
            }
        }
    }
    if let Some(context) = &native_context {
        for (id, header, result) in context.header_results(
            expected_headers.as_ref(),
            actual_headers.as_ref(),
            request_times,
        ) {
            let pointer = format!("$headers/{header}");
            if let Err(kind) = &result {
                report.unused_applicable_header_rule_ids.push(id);
                report
                    .differences
                    .push(ResponseDifference::header(&header, *kind));
            } else {
                report
                    .differences
                    .retain(|difference| difference.pointer != pointer);
                report.applied_header_rule_ids.push(id);
                report
                    .identity_pairs
                    .extend(result.expect("validated header JWT identities"));
            }
        }
    }
    if !body_available {
        report.finish(&[], &[]);
        return Ok(report);
    }
    let global_body_selected = loaded
        .compiled
        .as_ref()
        .and_then(|policy| policy.global_json.as_ref())
        .map(|plan| {
            if !plan.fields.is_empty() {
                return Ok(true);
            }
            // The implicit plan recognizes textual times in actual JSON
            // payloads. It does not replace native codecs or exact-body
            // diagnostics for unrelated bytes.
            if expected_body.body() == actual_body.body() {
                return Ok(false);
            }
            crate::json_value::parse(expected_body.body())
                .map(|source| {
                    plan.selected_fields_with_clocks(&source, clocks)
                        .map(|fields| !fields.is_empty())
                })
                .unwrap_or(Ok(false))
        })
        .transpose()?
        .unwrap_or(false);
    if global_body_selected && body_rules.is_empty()
        || native_context
            .as_ref()
            .is_some_and(|context| !context.is_empty())
    {
        let mut applicable_ids = Vec::new();
        if let Some(context) = native_context
            .as_ref()
            .filter(|context| !context.is_empty())
        {
            let codec = context.payload_codec(&[])?;
            ensure!(
                body_rules.is_empty()
                    || crate::value_codec::protobuf_schema(&codec).is_some()
                        && body_rules
                            .iter()
                            .all(|rule| rule.codec == ResponseBodyCodec::Protobuf),
                "native value contracts cannot consume another opaque body codec"
            );
            let comparison = context.compare_encoded_global(
                expected_body.body(),
                actual_body.body(),
                &[],
                loaded
                    .compiled
                    .as_ref()
                    .and_then(|p| p.global_json.as_ref()),
                clocks,
            )?;
            applicable_ids.extend(context.rule_ids());
            report.body_codec = if crate::value_codec::protobuf_schema(&codec).is_some() {
                ResponseBodyCodec::Protobuf
            } else {
                ResponseBodyCodec::Json
            };
            if report.body_codec == ResponseBodyCodec::Protobuf
                && !comparison.passed()
                && let Ok(mut diagnosis) = diagnose_response_body(
                    expected_body.body(),
                    actual_body.body(),
                    ResponseBodyCodec::Protobuf,
                )
            {
                diagnosis.configured = true;
                diagnosis.used_for_verdict = false;
                report.body_diagnosis = Some(diagnosis);
            }
            report.identity_pairs.extend(comparison.identity_pairs());
            report.applied_body_rule_ids.extend(comparison.evaluated);
            for diff in comparison.differences {
                report.differences.push(unified::contract_difference(diff));
            }
            if let Some(difference) = expected_body.type_difference(&actual_body) {
                report.differences.push(difference);
            }
            if !expected_body.gateway_metadata_matches(&actual_body) {
                report
                    .differences
                    .push(ResponseDifference::gateway_metadata_mismatch());
            }
        } else {
            ensure!(
                body_rules.is_empty(),
                "generic and native opaque body contracts require one compiled codec owner"
            );
            unified::compare(
                loaded
                    .compiled
                    .as_ref()
                    .and_then(|p| p.global_json.as_ref()),
                &expected_body,
                &actual_body,
                clocks,
                &mut report,
            )?;
        }
        applicable_ids.retain(|id| report.applied_body_rule_ids.contains(id));
        report.finish(&[], &applicable_ids);
        return Ok(report);
    }
    if let Some(rule) = body_rules.first() {
        ensure!(
            response_fields.is_empty(),
            "typed response-body rules cannot be combined with JSON response rules"
        );
        let (body_matches, body_diagnosis) = match rule.codec {
            crate::policy::runtime::ResponseBodyCodec::Protobuf => {
                let unordered_paths = rule
                    .unordered_paths
                    .iter()
                    .map(|path| match path {
                        crate::policy::runtime::ResponseBodyUnorderedPath::Protobuf(path) => {
                            Ok(path.clone())
                        }
                        crate::policy::runtime::ResponseBodyUnorderedPath::Hessian2(_) => {
                            anyhow::bail!(
                                "protobuf response-body rule contains a Hessian2 unordered path"
                            )
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                let joined_string_paths = rule
                    .unordered_joined_string_paths
                    .iter()
                    .map(|path| match path {
                        crate::policy::runtime::ResponseBodyJoinedStringPath::Protobuf(path) => {
                            Ok(path.clone())
                        }
                        crate::policy::runtime::ResponseBodyJoinedStringPath::Hessian2(_) => {
                            anyhow::bail!(
                                "protobuf response-body rule contains a Hessian2 joined-string path"
                            )
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                report.body_codec = ResponseBodyCodec::Protobuf;
                let (body_matches, discovery) = protobuf::evaluate_protobuf(
                    expected_body.body(),
                    actual_body.body(),
                    &unordered_paths,
                    &joined_string_paths,
                )
                .context("failed to apply configured protobuf response-body rule")?;
                (
                    body_matches,
                    ResponseBodyAssertionReport {
                        codec: rule.codec,
                        envelope: discovery.envelope.as_str().to_string(),
                        configured: true,
                        used_for_verdict: true,
                        codec_candidates: vec![rule.codec],
                        unordered_path_candidates: discovery
                            .unordered_paths
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                        unordered_joined_string_candidates: discovery
                            .unordered_joined_string_paths
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                        differences: discovery.differences.into_iter().map(Into::into).collect(),
                        candidates_explain_all_differences: discovery
                            .candidates_explain_all_differences,
                        order_only: discovery.order_only,
                    },
                )
            }
            crate::policy::runtime::ResponseBodyCodec::Hessian2 => {
                let unordered_paths = rule
                    .unordered_paths
                    .iter()
                    .map(|path| match path {
                        crate::policy::runtime::ResponseBodyUnorderedPath::Hessian2(path) => {
                            Ok(path.clone())
                        }
                        crate::policy::runtime::ResponseBodyUnorderedPath::Protobuf(_) => {
                            anyhow::bail!(
                                "Hessian2 response-body rule contains a protobuf unordered path"
                            )
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                let joined_string_paths = rule
                    .unordered_joined_string_paths
                    .iter()
                    .map(|path| match path {
                        crate::policy::runtime::ResponseBodyJoinedStringPath::Hessian2(path) => {
                            Ok(path.clone())
                        }
                        crate::policy::runtime::ResponseBodyJoinedStringPath::Protobuf(_) => {
                            anyhow::bail!(
                                "Hessian2 response-body rule contains a protobuf joined-string path"
                            )
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                report.body_codec = ResponseBodyCodec::Hessian2;
                let (body_matches, discovery) = hessian2::evaluate_hessian2(
                    expected_body.body(),
                    actual_body.body(),
                    &unordered_paths,
                    &joined_string_paths,
                )
                .context("failed to apply configured Hessian2 response-body rule")?;
                (
                    body_matches,
                    ResponseBodyAssertionReport {
                        codec: rule.codec,
                        envelope: discovery.envelope.as_str().to_string(),
                        configured: true,
                        used_for_verdict: true,
                        codec_candidates: vec![rule.codec],
                        unordered_path_candidates: discovery
                            .unordered_paths
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                        unordered_joined_string_candidates: discovery
                            .unordered_joined_string_paths
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                        differences: discovery.differences.into_iter().map(Into::into).collect(),
                        candidates_explain_all_differences: discovery
                            .candidates_explain_all_differences,
                        order_only: discovery.order_only,
                    },
                )
            }
            crate::policy::runtime::ResponseBodyCodec::Docx => {
                ensure!(
                    rule.unordered_paths.is_empty()
                        && rule.unordered_joined_string_paths.is_empty(),
                    "DOCX response-body rule cannot contain typed collection paths"
                );
                report.body_codec = ResponseBodyCodec::Docx;
                docx::evaluate_docx(
                    expected_body.body(),
                    actual_body.body(),
                    &rule.docx_timestamps,
                    times,
                )
                .context("failed to apply configured DOCX response-body rule")?
            }
            codec => anyhow::bail!("unsupported configured response-body codec {codec:?}"),
        };
        if loaded.compiled.is_some() {
            report.applied_body_rule_ids.extend(native_body_ids.clone());
        } else {
            report.applied_body_rule_ids.push(rule.id.clone());
        }
        report.body_diagnosis = Some(body_diagnosis);
        let body_type_difference = expected_body.type_difference(&actual_body);
        if !body_matches
            || body_type_difference.is_some()
            || !expected_body.gateway_metadata_matches(&actual_body)
        {
            if !body_matches {
                report
                    .differences
                    .push(ResponseDifference::body_value_mismatch());
            }
            if let Some(difference) = body_type_difference {
                report.differences.push(difference);
            }
            if !expected_body.gateway_metadata_matches(&actual_body) {
                report
                    .differences
                    .push(ResponseDifference::gateway_metadata_mismatch());
            }
        }
        report.finish(
            &[],
            if loaded.compiled.is_some() {
                &native_body_ids
            } else {
                std::slice::from_ref(&rule.id)
            },
        );
        return Ok(report);
    }

    if expected_body.protocol_body_codec() == Some(ResponseBodyCodec::Hessian2)
        && actual_body.protocol_body_codec() == Some(ResponseBodyCodec::Hessian2)
    {
        ensure!(
            response_fields.is_empty(),
            "JSON response rules cannot apply to a Motan1 Hessian2 value response"
        );
        report.body_codec = ResponseBodyCodec::Hessian2;
        let (body_matches, discovery) =
            hessian2::evaluate_hessian2(expected_body.body(), actual_body.body(), &[], &[])
                .context("failed to compare Motan1 Hessian2 value response bodies")?;
        report.body_diagnosis = Some(ResponseBodyAssertionReport {
            codec: ResponseBodyCodec::Hessian2,
            envelope: discovery.envelope.as_str().to_string(),
            configured: false,
            used_for_verdict: true,
            codec_candidates: vec![ResponseBodyCodec::Hessian2],
            unordered_path_candidates: discovery
                .unordered_paths
                .into_iter()
                .map(Into::into)
                .collect(),
            unordered_joined_string_candidates: discovery
                .unordered_joined_string_paths
                .into_iter()
                .map(Into::into)
                .collect(),
            differences: discovery.differences.into_iter().map(Into::into).collect(),
            candidates_explain_all_differences: discovery.candidates_explain_all_differences,
            order_only: discovery.order_only,
        });
        if !body_matches {
            report
                .differences
                .push(ResponseDifference::body_value_mismatch());
        }
        if let Some(difference) = expected_body.type_difference(&actual_body) {
            report.differences.push(difference);
        }
        if !expected_body.gateway_metadata_matches(&actual_body) {
            report
                .differences
                .push(ResponseDifference::gateway_metadata_mismatch());
        }
        report.finish(&[], &[]);
        return Ok(report);
    }

    match (
        serde_json::from_slice::<serde_json::Value>(expected_body.body()),
        serde_json::from_slice::<serde_json::Value>(actual_body.body()),
    ) {
        (Ok(expected), Ok(actual)) => {
            report.body_codec = ResponseBodyCodec::Json;
            let applicable_fields =
                compare_json(&expected, &actual, &response_fields, &mut report, clocks);
            if let Some(difference) = expected_body.type_difference(&actual_body) {
                report.differences.push(difference);
            }
            if !expected_body.gateway_metadata_matches(&actual_body) {
                report
                    .differences
                    .push(ResponseDifference::gateway_metadata_mismatch());
            }
            report.finish(&applicable_fields, &[]);
        }
        _ => {
            report.body_codec = ResponseBodyCodec::ExactBytes;
            let bodies_match = expected_body.body() == actual_body.body();
            let body_type_difference = expected_body.type_difference(&actual_body);
            // Configured response rules are JSON-pointer-based and cannot apply
            // to a non-JSON body. When the bodies are byte-equal there is no
            // difference for any rule to evaluate, so the case passes
            // regardless of configured rules. Only a differing non-JSON body
            // with configured rules is unevaluable, because the rules cannot
            // judge whether the difference would be tolerated.
            ensure!(
                (bodies_match && body_type_difference.is_none()) || response_fields.is_empty(),
                "response rules require JSON response bodies"
            );
            if !bodies_match {
                report
                    .differences
                    .push(ResponseDifference::exact_body_mismatch());
                let expected_body_value = expected_body.body();
                let actual_body_value = actual_body.body();
                if expected_body_value != actual_body_value {
                    let protobuf_candidate = protobuf::is_protobuf_body(expected_body_value)
                        && protobuf::is_protobuf_body(actual_body_value);
                    let hessian2_candidate = hessian2::is_hessian2_body(expected_body_value)
                        && hessian2::is_hessian2_body(actual_body_value);
                    let docx_candidate = docx::is_docx_body(expected_body_value)
                        && docx::is_docx_body(actual_body_value);
                    let mut codec_candidates = Vec::new();
                    if protobuf_candidate {
                        codec_candidates.push(crate::policy::runtime::ResponseBodyCodec::Protobuf);
                    }
                    if hessian2_candidate {
                        codec_candidates.push(crate::policy::runtime::ResponseBodyCodec::Hessian2);
                    }
                    if docx_candidate {
                        codec_candidates.push(crate::policy::runtime::ResponseBodyCodec::Docx);
                    }
                    let diagnostic_codec = if protobuf_candidate {
                        Some(ResponseBodyCodec::Protobuf)
                    } else if hessian2_candidate {
                        Some(ResponseBodyCodec::Hessian2)
                    } else if docx_candidate {
                        Some(ResponseBodyCodec::Docx)
                    } else {
                        None
                    };
                    if let Some(codec) = diagnostic_codec {
                        let mut diagnosis =
                            diagnose_response_body(expected_body_value, actual_body_value, codec)?;
                        diagnosis.codec_candidates = codec_candidates;
                        report.body_codec = codec;
                        report.body_diagnosis = Some(diagnosis);
                    }
                }
            }
            if let Some(difference) = body_type_difference {
                report.differences.push(difference);
            }
            if !expected_body.gateway_metadata_matches(&actual_body) {
                report
                    .differences
                    .push(ResponseDifference::gateway_metadata_mismatch());
            }
            report.finish(&[], &[]);
        }
    }
    Ok(report)
}
