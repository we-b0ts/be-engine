//! Prove a finite async tail from the effective immutable Source scope.
use super::*;
use serde_json::Value;

#[cfg(test)]
mod tests;

pub(super) async fn from_complete_source(
    case_dir: &Path,
    rules: &BTreeMap<String, crate::policy::AsyncApiRules>,
    request_timeout: Duration,
) -> Result<Option<Metadata>> {
    from_scope(
        case_dir,
        &case_dir.join("dependencies.jsonl"),
        rules,
        request_timeout,
    )
    .await
}

pub(super) async fn from_scope(
    case_dir: &Path,
    dependency_path: &Path,
    rules: &BTreeMap<String, crate::policy::AsyncApiRules>,
    request_timeout: Duration,
) -> Result<Option<Metadata>> {
    if rules.is_empty() {
        return Ok(None);
    }
    let raw = read(&case_dir.join("request.json"))
        .await?
        .context("async API replay requires an original Source request")?;
    let request: Value = serde_json::from_slice(&raw).context("invalid async Source request")?;
    let method = request["method"]
        .as_str()
        .context("async Source method unavailable")?
        .parse()?;
    let uri = request["uri"]
        .as_str()
        .context("async Source URI unavailable")?
        .parse()?;
    let body = crate::replay::native_source_request_body(&request)
        .map(|body| serde_json::to_vec(&body))
        .transpose()?
        .unwrap_or_default();
    let Some(scope) =
        crate::recorder::async_api::AsyncScope::for_primary(rules, &method, &uri, &body)
    else {
        return Ok(None);
    };
    let raw_response = read(&case_dir.join("expected-response.json"))
        .await?
        .context("async API fallback requires a complete published Source response")?;
    let response: Value =
        serde_json::from_slice(&raw_response).context("invalid async Source response")?;
    let response_body = crate::replay::native_source_request_body(&response);
    if !scope.select_response(response_body.as_ref()).0 {
        return Ok(None);
    }
    let path = dependency_path.to_owned();
    let raw =
        tokio::task::spawn_blocking(move || crate::dependency_index::scoped::read_bytes(&path))
            .await
            .context("async dependency scope read task failed")??;
    let (references, source_stop_required) =
        tokio::task::spawn_blocking(move || complete_inventory(&scope, &raw))
            .await
            .context("async Source inventory preparation task failed")??;
    let request_timeout_ms = request_timeout
        .as_millis()
        .try_into()
        .context("async API request budget exceeds its bound")?;
    Ok(Some(Metadata {
        recorded_idle_completion: false,
        normal_completion: true,
        request_timeout_ms,
        interaction_post_input_ms: None,
        strict_references: references.clone(),
        references: references.into_iter().collect(),

        source_stop_required,
        source_stop_after_ms: None,
        cleanup_refs: BTreeSet::new(),
        failure_completion: source_stop_required,
        timeout_completion: false,
    }))
}

fn complete_inventory(
    scope: &crate::recorder::async_api::AsyncScope,
    raw: &[u8],
) -> Result<(BTreeSet<RecordedReference>, bool)> {
    let mut references = BTreeSet::new();
    let mut completed = false;
    let mut source_stop_required = false;
    for line in raw
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
    {
        let event: Value =
            serde_json::from_slice(line).context("invalid async Source dependency")?;
        if let Some(signal) = scope.observe_recorded(&event)? {
            completed = true;
            source_stop_required |=
                signal.end_reason != crate::recorder::async_api::AsyncEndReason::Resource;
        }
        if let Some(reference) = reference(&event)? {
            ensure!(
                references.insert(reference),
                "async Source inventory repeats an exchange"
            );
            ensure!(
                references.len() <= MAX_SELECTED_REFS,
                "async Source inventory exceeds its bound"
            );
        }
    }
    ensure!(
        completed,
        "async API Source inventory has no proven completion resource; record a complete async case"
    );
    Ok((references, source_stop_required))
}
