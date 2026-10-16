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
    ordinary: &[&CompiledRule],
    native: &[&CompiledNativeRule],
    result: &mut Preflight,
) -> Result<()> {
    let summary = bundle.assertions["cases"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["case_id"] == case))
        .map(|item| item["response"].clone())
        .unwrap_or(Value::Null);
    let expected = summary["expected_response"]
        .as_str()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| directory.join("expected-response.json"));
    let source = bundle.json(&expected)?;
    ensure!(
        source == bundle.json(&directory.join("expected-response.json"))?,
        "primary Source response does not match the prepared immutable Case"
    );
    let context = NativeResponseContext::from_rules(native, root, directory)?;
    for (path, digest) in context.key_witnesses() {
        bundle.freeze(path)?;
        ensure!(
            bundle.artifacts[path].sha256 == *digest,
            "API signing/encryption input changed between resolution and evidence freezing"
        );
    }
    context.ensure_current()?;
    let source_payload = crate::replay::response_payload_pair(request, &source, None)?;
    let clocks = AnchorClocks {
        case: crate::value_contract::time::ClockPair {
            source: source_payload.times.source,
            target: source_payload.times.source,
        },
        ..Default::default()
    };
    let checked = compare_payload(
        &source_payload.source,
        &source_payload.source,
        ordinary,
        native,
        &context,
        clocks,
    )?;
    let mut source_ids = checked;
    for rule in native {
        if let NativeEffect::ResponseHeaderDate(effect) = &rule.rule.effect {
            let values = header(&source_payload.source_headers, &effect.header);
            if !values.is_empty() {
                ensure!(
                    crate::replay::native_response_header(rule, &values, &values, clocks.case)?,
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
    let Some(actual) = summary["actual_response"].as_str() else {
        result.missing_target_witnesses += 1;
        return Ok(());
    };
    let detail_path = summary["detail_report"]
        .as_str()
        .context("Target response has no runner-owned assertion detail")?;
    let detail = bundle.json(Path::new(detail_path))?;
    ensure!(
        crate::verification_progress::fingerprint(&fs::read(detail_path)?)
            == summary["detail_fingerprint"]
                .as_str()
                .context("assertion detail fingerprint missing")?
            && detail["case_id"] == case
            && detail["expected_response_path"] == expected.to_string_lossy().as_ref()
            && detail["actual_response_path"] == actual,
        "response assertion detail identity changed after publication"
    );
    let target = bundle.json(Path::new(actual))?;
    for (path, field) in [
        (expected.as_path(), "expected_response_fingerprint"),
        (Path::new(actual), "actual_response_fingerprint"),
    ] {
        ensure!(
            detail[field].as_str()
                == Some(crate::verification_progress::fingerprint(&fs::read(path)?).as_str()),
            "primary response bytes changed after assertion publication"
        );
    }
    let pair = crate::replay::response_payload_pair(request, &source, Some(&target))?;
    let clocks = AnchorClocks {
        case: pair.times,
        ..Default::default()
    };
    compare_payload(
        &pair.source,
        pair.target
            .as_deref()
            .context("independent Target response is unavailable")?,
        ordinary,
        native,
        &context,
        clocks,
    )?;
    compare_headers(
        native,
        &pair.source_headers,
        &pair.target_headers,
        pair.times,
    )?;
    if !source_ids.is_empty() {
        result.independent_target_validations += 1;
    }
    Ok(())
}

fn compare_payload(
    source: &[u8],
    target: &[u8],
    ordinary: &[&CompiledRule],
    native: &[&CompiledNativeRule],
    context: &NativeResponseContext,
    clocks: AnchorClocks,
) -> Result<BTreeSet<String>> {
    let opaque=native.iter().copied().filter(|rule|
        matches!(&rule.rule.effect,NativeEffect::ResponseBody(effect) if matches!(effect.codec,BodyCodec::Hessian2|BodyCodec::Docx))
    ).collect::<Vec<_>>();
    if !opaque.is_empty() {
        ensure!(
            ordinary.is_empty() && context.is_empty(),
            "opaque API body requires one compiled codec owner"
        );
        ensure!(
            crate::replay::native_response_body(&opaque, source, target, clocks.case)?,
            "Source/Target opaque response contract failed"
        );
        return Ok(opaque.iter().map(|rule| rule.rule.id.clone()).collect());
    }
    if !ordinary.is_empty() || !context.is_empty() {
        let comparison = context.compare_encoded(source, target, ordinary, clocks)?;
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
