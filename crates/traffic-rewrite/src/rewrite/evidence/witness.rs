//! Bounded on-demand values from authenticated, issue-bound dependency witnesses.
use super::*;
use crate::policy::Protocol;
use crate::policy_evidence::{SourceIdentity, TargetRole, WitnessManifest};
use crate::rewrite::{RewriteContext, store::RewriteStore};
mod values;

pub fn query_rewrite_witness_for_scope(
    context: RewriteContext,
    scope: &RewriteWorkScope,
    witness_id: &str,
    pointer: &str,
    value_index: usize,
) -> Result<RewriteEvidenceReport> {
    anyhow::ensure!(
        pointer.starts_with('/') && pointer.len() <= 1024,
        "select a bounded non-root JSON pointer"
    );
    anyhow::ensure!(
        witness_id.len() <= 1024 && value_index < 128,
        "witness selector exceeds supported bounds"
    );
    let root = crate::e2e_run::resolve_project(&context.target_root)?.0;
    let state = RewriteStore::new(&root)?
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let RewriteWorkScope::Api { api } = scope;
    let state = super::super::api_selector::scoped(&state, api)?;
    let scope = super::super::api_selector::work_scope(&state, api);
    let issue = state
        .active_issue
        .as_ref()
        .context("API has no current issue")?;
    super::super::worker::ensure_scope_confirmed(&state, &scope, "querying protected witness")?;
    let context = e2e_context(&root, &state)?;
    let summary =
        crate::e2e_run::finalized_focused_attempt_summary(context.clone(), group_id(&state)?)?;
    anyhow::ensure!(
        summary.attempt == issue.attempt,
        "witness attempt differs from the active issue; query fresh evidence"
    );
    let evidence = crate::resolve_e2e_response_rule_evidence(context, group_id(&state)?)?;
    let bytes = std::fs::read(&evidence.replay)?;
    let replay: Value = serde_json::from_slice(&bytes)?;
    let manifest: WitnessManifest = serde_json::from_value(replay["policy_witnesses"].clone())?;
    anyhow::ensure!(
        manifest.complete && manifest.sealed,
        "protected witness publication is incomplete"
    );
    let private = crate::policy_evidence::verify(&evidence.replay, &manifest)?;
    let mut found = None;
    for entry in manifest.witness_entries()? {
        let witness = entry?.expand()?;
        if witness.as_ref().id == witness_id {
            anyhow::ensure!(found.is_none(), "ambiguous witness identity");
            found = Some(witness);
        }
    }
    let witness = found.context("witness is not present in this API's current attempt")?;
    let witness = witness.as_ref();
    let identity = &witness.metadata.source;
    let case = replay["cases"]
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["case_id"] == identity.case_id)
        })
        .context("witness is outside this API's selected cases")?;
    let directory = Path::new(
        case["case_dir"]
            .as_str()
            .context("witness case directory is unavailable")?,
    );
    crate::policy_evidence::verify_case_clock(witness, &replay)?;
    let (source, target) = crate::policy_evidence::read(&private, witness, directory)?;
    let protocol = witness
        .metadata
        .resource
        .as_ref()
        .context("witness has no dependency resource")?
        .protocol;
    let event = source_event(directory, identity, protocol)?;
    let original = super::super::unified_rule::dependency_source_witness(
        witness.metadata.surface,
        &event,
        directory,
    )?;
    anyhow::ensure!(
        crate::policy_evidence::digest(&original) == witness.source_sha256,
        "witness Source event changed"
    );
    let providers = crate::protocols::default_providers();
    let query = traffic_protocol::evidence::ValueQuery {
        side: witness.metadata.surface.dependency_side()?,
        value_index,
        pointer,
    };
    let reader = values::Reader(crate::value_extensions::codecs());
    let project = |raw: &[u8]| {
        providers
            .evidence()
            .query_value(&event, raw, query, &reader)?
            .context("native witness value projection is unavailable")
    };
    let source = project(&source)?;
    let independent = witness.metadata.target_role == TargetRole::IndependentTargetObservation;
    let target = target
        .as_deref()
        .filter(|_| independent)
        .map(project)
        .transpose()?;
    let raw_request: Value =
        serde_json::from_slice(&std::fs::read(directory.join("request.json"))?)?;
    let request: Value = serde_json::from_slice(&crate::request_headers::load_request_file(
        &directory.join("request.json"),
    )?)?;
    let header_names = request["headers"]
        .as_object()
        .map(|headers| headers.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let mut facts = json!({
        "attempt":issue.attempt,"recording_run_id":state.recording_run_id,
        "report_sha256":crate::policy_evidence::digest(&bytes),
        "witness_id":witness.id,"metadata":witness.metadata,
        "representation":source.representation,
        "value_index":value_index,"pointer":pointer,
        "source_document_count":source.document_count,
        "target_document_count":target.as_ref().map(|projection| projection.document_count),
        "source":source.observation,
        "target":target.as_ref().map(|projection| &projection.observation)
            .map(serde_json::to_value).transpose()?
            .unwrap_or_else(|| json!({"presence":"unavailable","reason":"witness is not an independent Target observation"})),
        "recorded_request_context":{"header_names":header_names,"headers_encrypted_at_rest":crate::request_headers::has_encrypted_request_headers(&raw_request)}
    });
    let fields = facts.as_object_mut().expect("witness facts are an object");
    anyhow::ensure!(
        source
            .annotations
            .keys()
            .all(|name| !fields.contains_key(name)),
        "native value annotations would replace protected witness facts"
    );
    fields.extend(source.annotations);
    let mut report =
        super::report::selected(&root, &state, &scope, issue, "dependency_witness", facts)?;
    report.does_not_prove = vec!["A retained candidate proves observed bytes, not a successful dependency match or authorization for a rule.".into()];
    report.next_step = "Trace the selected observed difference through Source and Target code. Recorded request header names come from authenticated input; public encrypted-header placeholders do not establish absence. Use narrower pointers for unavailable large values.".into();
    Ok(report)
}

fn source_event(directory: &Path, identity: &SourceIdentity, protocol: Protocol) -> Result<Value> {
    anyhow::ensure!(
        identity.exchange_id.is_some()
            || identity.connection_id.is_some() && identity.sequence.is_some(),
        "witness has no original Source exchange identity"
    );
    let expected_protocol = serde_json::to_value(protocol)?;
    let providers = crate::protocols::default_providers();
    let path = directory.join("dependencies.jsonl");
    let mut reader = crate::dependency_index::RecordStream::open(&path)?;
    while let Some((_, line)) = reader.next()? {
        anyhow::ensure!(
            line.len() <= crate::dependency::http_limits::MAX_RECORD_BYTES,
            "witness Source record exceeds supported bounds"
        );
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let event: Value = serde_json::from_slice(line)?;
        if !providers
            .event_provider(&event)
            .is_some_and(|owner| expected_protocol == owner.kind.as_str())
        {
            continue;
        }
        let matched =
            super::super::unified_rule::dependency_source_identity(&identity.case_id, &event)
                .is_some_and(|observed| observed == *identity);
        if matched {
            return Ok(event);
        }
    }
    anyhow::bail!("witness original Source event is unavailable")
}
