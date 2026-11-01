//! Preflight facades use the same typed projection and codec owners as Replay.
use anyhow::{Context, Result, ensure};

use crate::policy::{CompiledNativeRule, NativeEffect};
use crate::replay::policy::{
    ResponseBodyCodec, ResponseBodyJoinedStringPath, ResponseBodyUnorderedPath,
};

pub(in crate::replay::assertion) fn merge_opaque(
    mut rules: Vec<crate::replay::policy::ResponseBodyRuleMatch>,
) -> Result<Vec<crate::replay::policy::ResponseBodyRuleMatch>> {
    if rules.len() <= 1 {
        return Ok(rules);
    }
    let mut owner = rules.remove(0);
    for rule in rules {
        ensure!(
            owner.codec == rule.codec,
            "one response cannot use two opaque codecs"
        );
        owner.unordered_paths.extend(rule.unordered_paths);
        owner
            .unordered_joined_string_paths
            .extend(rule.unordered_joined_string_paths);
        owner.docx_timestamps.extend(rule.docx_timestamps);
    }
    Ok(vec![owner])
}

pub(crate) fn compare_header(
    rule: &CompiledNativeRule,
    source: &[String],
    target: &[String],
    times: super::super::RequestTimes,
) -> Result<bool> {
    let NativeEffect::ResponseHeaderDate(_) = &rule.rule.effect else {
        anyhow::bail!("not a response header contract")
    };
    let projected =
        crate::replay::policy::native_projection::project_native(std::slice::from_ref(rule))?;
    let fields = projected
        .document
        .response_rules
        .headers
        .values()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        !source
            .iter()
            .chain(target)
            .any(|value| value == "<redacted>"),
        "header evidence is unavailable"
    );
    super::super::headers::date::compare(source, target, &fields, times)
}

pub(crate) fn compare_body(
    rules: &[&CompiledNativeRule],
    source: &[u8],
    target: &[u8],
    times: super::super::RequestTimes,
) -> Result<bool> {
    ensure!(
        !rules.is_empty()
            && rules
                .iter()
                .all(|rule| matches!(rule.rule.effect, NativeEffect::ResponseBody(_))),
        "body facade requires body contracts"
    );
    let api = rules[0]
        .rule
        .selector
        .api
        .as_deref()
        .context("native body API absent")?;
    let _ = api;
    let projected = crate::replay::policy::native_projection::project_native(
        &rules.iter().copied().cloned().collect::<Vec<_>>(),
    )?;
    let mut selected = vec![];
    for api in rules
        .iter()
        .filter_map(|rule| rule.rule.selector.api.as_deref())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let (method, path) = api.split_once(' ').context("native body API invalid")?;
        selected.extend(
            projected
                .document
                .response_rules
                .matching_response_body_rules(method, path)
                .into_iter()
                .filter(|rule| rule.api == api),
        );
    }
    let selected = merge_opaque(selected)?;
    ensure!(
        selected.len() == 1,
        "body contract requires one compiled opaque codec owner"
    );
    let rule = &selected[0];
    match rule.codec {
        ResponseBodyCodec::Protobuf => {
            let context = super::NativeResponseContext::from_rules(
                rules,
                std::path::Path::new("."),
                std::path::Path::new("."),
            )?;
            Ok(context
                .compare_encoded(
                    source,
                    target,
                    &[],
                    crate::value_contract::json::AnchorClocks::for_response(
                        Default::default(),
                        times,
                    ),
                )?
                .passed())
        }
        ResponseBodyCodec::Hessian2 => {
            let unordered = rule
                .unordered_paths
                .iter()
                .map(|path| match path {
                    ResponseBodyUnorderedPath::Hessian2(path) => Ok(path.clone()),
                    _ => anyhow::bail!("mixed body codecs"),
                })
                .collect::<Result<Vec<_>>>()?;
            let joined = rule
                .unordered_joined_string_paths
                .iter()
                .map(|path| match path {
                    ResponseBodyJoinedStringPath::Hessian2(path) => Ok(path.clone()),
                    _ => anyhow::bail!("mixed body codecs"),
                })
                .collect::<Result<Vec<_>>>()?;
            super::super::hessian2::compare_hessian2(source, target, &unordered, &joined)
        }
        ResponseBodyCodec::Docx => {
            Ok(super::super::docx::evaluate_docx(source, target, &rule.docx_timestamps, times)?.0)
        }
        _ => anyhow::bail!("not an opaque body codec"),
    }
}
