//! API payloads retain the native artifact/carrier and typed field proof owners.
use super::*;
use crate::policy::{CompiledNativeRule, NativeEffect, native::BodyCodec};
use crate::replay::NativeResponseContext;

pub(super) fn is_response(rule: &CompiledNativeRule) -> bool {
    matches!(
        rule.rule.effect,
        NativeEffect::ResponseGenerated(_)
            | NativeEffect::ResponseJwt(_)
            | NativeEffect::ResponseHeaderDate(_)
            | NativeEffect::ResponseBody(_)
    )
}

#[allow(clippy::too_many_arguments)] // One immutable case/attempt defines every response proof owner.
pub(super) fn verify(
    root: &Path,
    bundle: &mut Bundle,
    case: &str,
    directory: &Path,
    request: &Value,
    global: Option<&crate::policy::CompiledJsonPolicy>,
    native: &[&CompiledNativeRule],
    result: &mut Preflight,
) -> Result<()> {
    let super::super::manifest::PrimaryResponse { source, target } =
        bundle.primary_response(case, directory)?;
    let source_payload = crate::replay::response_payload_pair(request, &source, None)?;
    let native = native
        .iter()
        .copied()
        .filter(|rule| source_payload.body_available || !rule.rule.effect.is_response_body())
        .collect::<Vec<_>>();
    let context = NativeResponseContext::from_rules(&native, root, directory)?;
    for (path, digest) in context.key_witnesses() {
        bundle.freeze(path)?;
        ensure!(
            bundle.artifacts[path].sha256 == *digest,
            "API signing/encryption input changed between resolution and evidence freezing"
        );
    }
    context.ensure_current()?;
    let source_times = crate::value_contract::time::ClockPair {
        source: source_payload.times.source,
        target: source_payload.times.source,
    };
    let clocks = AnchorClocks::for_response(
        crate::value_contract::time::ClockPair {
            source: source_payload.request_times.source,
            target: source_payload.request_times.source,
        },
        source_times,
    );
    let checked = compare_payload(
        &source_payload.source,
        &source_payload.source,
        global,
        &native,
        &context,
        clocks,
    )?;
    let mut source_ids = checked;
    for (id, _, result) in context.header_results(
        source_payload.source_headers.as_ref(),
        source_payload.source_headers.as_ref(),
        clocks.case,
    ) {
        ensure!(
            result.is_ok(),
            "Source header JWT {id:?} failed: {result:?}"
        );
        source_ids.insert(id);
    }
    for rule in &native {
        if let NativeEffect::ResponseHeaderDate(effect) = &rule.rule.effect {
            let values = header(&source_payload.source_headers, &effect.header);
            if !values.is_empty() {
                ensure!(
                    crate::replay::native_response_header(
                        rule,
                        &values,
                        &values,
                        clocks.observation(),
                    )?,
                    "Source header-date contract {:?} failed",
                    rule.rule.id
                );
                source_ids.insert(rule.rule.id.clone());
            }
        }
    }
    if source_ids.is_empty() {
        result.unavailable_source_values += 1;
    } else {
        result.source_validations += 1;
    }
    for id in &source_ids {
        *result.rules.entry(id.clone()).or_default() += 1;
    }
    let Some(target) = target else {
        result.missing_target_witnesses += 1;
        return Ok(());
    };
    let Some(pair) = super::response::target_pair(request, &source, &target, case, result)? else {
        return Ok(());
    };
    let clocks = AnchorClocks::for_response(pair.request_times, pair.times);
    compare_payload(
        &pair.source,
        pair.target
            .as_deref()
            .context("independent Target response is unavailable")?,
        global,
        &native,
        &context,
        clocks,
    )?;
    compare_headers(
        &native,
        &pair.source_headers,
        &pair.target_headers,
        pair.times,
    )?;
    for (id, _, result) in context.header_results(
        pair.source_headers.as_ref(),
        pair.target_headers.as_ref(),
        pair.request_times,
    ) {
        ensure!(
            result.is_ok(),
            "independent Target header JWT {id:?} failed: {result:?}"
        );
    }
    if !source_ids.is_empty() {
        result.independent_target_validations += 1;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compare_payload(
    source: &[u8],
    target: &[u8],
    global: Option<&crate::policy::CompiledJsonPolicy>,
    native: &[&CompiledNativeRule],
    context: &NativeResponseContext,
    clocks: AnchorClocks,
) -> Result<BTreeSet<String>> {
    let opaque=native.iter().copied().filter(|rule|
        matches!(&rule.rule.effect,NativeEffect::ResponseBody(effect) if matches!(effect.codec,BodyCodec::Hessian2|BodyCodec::Docx))
    ).collect::<Vec<_>>();
    if !opaque.is_empty() {
        ensure!(
            context.is_empty(),
            "opaque API body requires one compiled codec owner"
        );
        ensure!(
            crate::replay::native_response_body(&opaque, source, target, clocks.observation())?,
            "Source/Target opaque response contract failed"
        );
        return Ok(opaque.iter().map(|rule| rule.rule.id.clone()).collect());
    }
    if !context.is_empty() {
        let comparison = context.compare_encoded_global(source, target, &[], global, clocks)?;
        ensure!(
            comparison.passed(),
            "API response contract failed: {}",
            serde_json::to_string(&comparison.differences)?
        );
        return Ok(comparison.evaluated);
    }
    ensure!(source == target, "unselected API response body changed");
    Ok(BTreeSet::new())
}

fn header(headers: &Option<crate::recorder::HeaderMapSnapshot>, name: &str) -> Vec<String> {
    headers
        .as_ref()
        .into_iter()
        .flat_map(|headers| headers.iter())
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .flat_map(|(_, values)| values.iter().cloned())
        .collect()
}

fn compare_headers(
    rules: &[&CompiledNativeRule],
    source_headers: &Option<crate::recorder::HeaderMapSnapshot>,
    target_headers: &Option<crate::recorder::HeaderMapSnapshot>,
    times: crate::value_contract::time::ClockPair,
) -> Result<()> {
    for rule in rules {
        if let NativeEffect::ResponseHeaderDate(effect) = &rule.rule.effect {
            let source = header(source_headers, &effect.header);
            let target = header(target_headers, &effect.header);
            if source.is_empty() && target.is_empty() {
                continue;
            }
            ensure!(
                crate::replay::native_response_header(rule, &source, &target, times)?,
                "response header-date contract {:?} failed",
                rule.rule.id
            );
        }
    }
    Ok(())
}
