//! Bounded structured body evidence and pure configured content comparison.
use crate::{docx, model::ResponseBodyAssertionReport, protobuf, time::RequestTimes};
use anyhow::{Context, Result, ensure};
use traffic_policy_schema::response::{ResponseBodyCodec, ResponseBodyRuleMatch};
type BodyRecognizer = fn(&[u8]) -> bool;

pub fn diagnose(
    policies: &traffic_policy::PolicyRegistry,
    expected: &[u8],
    actual: &[u8],
    codec: ResponseBodyCodec,
) -> Result<ResponseBodyAssertionReport> {
    match codec {
        ResponseBodyCodec::Protobuf => {
            let discovery = protobuf::discover_protobuf_order(policies, expected, actual)?;
            Ok(ResponseBodyAssertionReport {
                codec,
                envelope: discovery.envelope.as_str().to_string(),
                configured: false,
                used_for_verdict: false,
                codec_candidates: vec![codec],
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
            })
        }
        ResponseBodyCodec::Hessian2 => anyhow::bail!("Hessian2 response comparison is disabled"),
        #[cfg(any())]
        ResponseBodyCodec::Hessian2 => {
            let discovery = hessian2::discover_hessian2_order(policies, expected, actual)?;
            Ok(ResponseBodyAssertionReport {
                codec,
                envelope: discovery.envelope.as_str().to_string(),
                configured: false,
                used_for_verdict: false,
                codec_candidates: vec![codec],
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
            })
        }
        ResponseBodyCodec::Docx => docx::diagnose_docx(policies, expected, actual),
        codec => anyhow::bail!("unsupported structured response body codec {codec:?}"),
    }
}

pub fn evaluate(
    policies: &traffic_policy::PolicyRegistry,
    rule: &ResponseBodyRuleMatch,
    expected: &[u8],
    actual: &[u8],
    times: RequestTimes,
) -> Result<(bool, ResponseBodyAssertionReport)> {
    Ok(match rule.codec {
        traffic_policy_schema::response::ResponseBodyCodec::Protobuf => {
            let unordered_paths = rule
                .unordered_paths
                .iter()
                .map(|path| match path {
                    traffic_policy_schema::response::ResponseBodyUnorderedPath::Protobuf(path) => {
                        Ok(path.clone())
                    }
                    traffic_policy_schema::response::ResponseBodyUnorderedPath::Hessian2(_) => {
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
                    traffic_policy_schema::response::ResponseBodyJoinedStringPath::Protobuf(
                        path,
                    ) => Ok(path.clone()),
                    traffic_policy_schema::response::ResponseBodyJoinedStringPath::Hessian2(_) => {
                        anyhow::bail!(
                            "protobuf response-body rule contains a Hessian2 joined-string path"
                        )
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            let (body_matches, discovery) = protobuf::evaluate_protobuf(
                policies,
                expected,
                actual,
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
        ResponseBodyCodec::Hessian2 => anyhow::bail!("Hessian2 response comparison is disabled"),
        #[cfg(any())]
        ResponseBodyCodec::Hessian2 => {
            let unordered_paths = rule
                .unordered_paths
                .iter()
                .map(|path| match path {
                    traffic_policy_schema::response::ResponseBodyUnorderedPath::Hessian2(path) => {
                        Ok(path.clone())
                    }
                    traffic_policy_schema::response::ResponseBodyUnorderedPath::Protobuf(_) => {
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
                    traffic_policy_schema::response::ResponseBodyJoinedStringPath::Hessian2(
                        path,
                    ) => Ok(path.clone()),
                    traffic_policy_schema::response::ResponseBodyJoinedStringPath::Protobuf(_) => {
                        anyhow::bail!(
                            "Hessian2 response-body rule contains a protobuf joined-string path"
                        )
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            let (body_matches, discovery) = hessian2::evaluate_hessian2(
                policies,
                expected,
                actual,
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
        traffic_policy_schema::response::ResponseBodyCodec::Docx => {
            ensure!(
                rule.unordered_paths.is_empty() && rule.unordered_joined_string_paths.is_empty(),
                "DOCX response-body rule cannot contain typed collection paths"
            );
            docx::evaluate_docx(policies, expected, actual, &rule.docx_timestamps, times)
                .context("failed to apply configured DOCX response-body rule")?
        }
        codec => anyhow::bail!("unsupported configured response-body codec {codec:?}"),
    })
}

/// The native carrier declares its content representation before value comparison.
pub fn compare_declared(
    policies: &traffic_policy::PolicyRegistry,
    codec: ResponseBodyCodec,
    expected: &[u8],
    actual: &[u8],
) -> Result<(bool, ResponseBodyAssertionReport)> {
    let rule = ResponseBodyRuleMatch {
        id: String::new(),
        api: String::new(),
        codec,
        unordered_paths: vec![],
        unordered_joined_string_paths: vec![],
        docx_timestamps: vec![],
    };
    let (matched, mut diagnosis) =
        evaluate(policies, &rule, expected, actual, RequestTimes::default())?;
    diagnosis.configured = false;
    Ok((matched, diagnosis))
}

/// Ambiguous recognition remains visible in the diagnostic candidate list.
pub fn discover(
    policies: &traffic_policy::PolicyRegistry,
    expected: &[u8],
    actual: &[u8],
) -> Result<Option<ResponseBodyAssertionReport>> {
    let recognizers: &[(ResponseBodyCodec, BodyRecognizer)] = &[
        (ResponseBodyCodec::Protobuf, protobuf::is_protobuf_body),
        (ResponseBodyCodec::Docx, docx::is_docx_body),
    ];
    let candidates = recognizers
        .iter()
        .filter(|(_, recognizes)| recognizes(expected) && recognizes(actual))
        .map(|(codec, _)| *codec)
        .collect::<Vec<_>>();
    let Some(codec) = candidates.first() else {
        return Ok(None);
    };
    let mut diagnosis = diagnose(policies, expected, actual, *codec)?;
    diagnosis.codec_candidates = candidates;
    Ok(Some(diagnosis))
}
