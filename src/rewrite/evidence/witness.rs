//! Bounded on-demand values from authenticated, issue-bound dependency witnesses.
use super::*;
use crate::policy::{Protocol, Surface};
use crate::policy_evidence::{SourceIdentity, TargetRole, WitnessManifest};
use crate::rewrite::{RewriteContext, store::RewriteStore};
mod mysql;

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
    let redis_arguments = if protocol == Protocol::Redis {
        Some(serde_json::from_slice::<Vec<Vec<u8>>>(
            &super::super::unified_rule::dependency_source_witness(
                Surface::DependencyRequest,
                &event,
                directory,
            )?,
        )?)
    } else {
        None
    };
    let documents = |raw: &[u8]| -> Result<Vec<Vec<u8>>> {
        if protocol == Protocol::Mysql {
            Ok(vec![raw.to_vec()])
        } else if let Some(arguments) = redis_arguments.as_ref() {
            let actual;
            let arguments = if witness.metadata.surface == Surface::DependencyRequest {
                actual = serde_json::from_slice::<Vec<Vec<u8>>>(raw)?;
                &actual
            } else {
                arguments
            };
            if witness.metadata.operation == "PUBLISH"
                && witness.metadata.surface == Surface::DependencyRequest
            {
                return Ok(vec![
                    arguments
                        .get(1)
                        .context("PUBLISH payload is unavailable")?
                        .clone(),
                ]);
            }
            Ok(crate::replay::redis_field_values(
                &witness.metadata.operation,
                arguments,
                (witness.metadata.surface == Surface::DependencyResponse).then_some(raw),
            )?
            .into_iter()
            .map(|field| field.payload.unwrap_or_default().to_vec())
            .collect())
        } else {
            Ok(super::super::unified_rule::dependency_witness_values(
                witness.metadata.surface,
                &event,
                raw,
            )?
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect())
        }
    };
    let source = documents(&source)?;
    let independent = witness.metadata.target_role == TargetRole::IndependentTargetObservation;
    let target = target
        .as_deref()
        .filter(|_| independent)
        .map(documents)
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
    let sql_values =
        protocol == Protocol::Mysql && mysql::is_selector(pointer, witness.metadata.surface);
    let observe = |raw| {
        if sql_values {
            mysql::observation(
                raw,
                pointer,
                witness.metadata.surface,
                witness
                    .metadata
                    .resource
                    .as_ref()
                    .and_then(|resource| resource.database.as_ref())
                    .and_then(crate::policy::Database::name),
            )
        } else {
            observation(raw, pointer)
        }
    };
    let mut facts = json!({
        "attempt":issue.attempt,"recording_run_id":state.recording_run_id,
        "report_sha256":crate::policy_evidence::digest(&bytes),
        "witness_id":witness.id,"metadata":witness.metadata,
        "representation":if sql_values {"materialized_mysql_sql_value"} else if protocol == Protocol::Mysql {"native_witness_json"} else {"logical_json"},
        "value_index":value_index,"pointer":pointer,
        "source_document_count":source.len(),"target_document_count":target.as_ref().map(Vec::len),
        "source":observe(source.get(value_index).map(Vec::as_slice)),
        "target":if independent {observe(target.as_ref().and_then(|values| values.get(value_index)).map(Vec::as_slice))} else {json!({"presence":"unavailable","reason":"witness is not an independent Target observation"})},
        "recorded_request_context":{"header_names":header_names,"headers_encrypted_at_rest":crate::request_headers::has_encrypted_request_headers(&raw_request)}
    });
    if protocol == Protocol::Mysql {
        facts["sql_value_selection"] = json!({
            "request_pointer":"/sql_values/<sql-token-index>/value",
            "response_request_pointer":"/request/sql_values/<sql-token-index>/value",
            "decoded_json_pointer":"/sql_values/<sql-token-index>/json/<json-pointer>",
            "physical_field_pointer":"/sql_values/<sql-token-index>/field",
            "position_source":"physical_fields.fields[].observed_positions in unified-rule-candidates uses the same SQL token indexes",
            "semantics":"Each statement is materialized independently. Numbers retain exact normalized SQL text; strings preserve decoded native bytes. A field origin or decoded JSON view grants no matching permission and does not prove the two selected cells correspond."
        });
    }
    let id = overview::query_id(&state, &scope, issue);
    let mut report = overview::report(&root, &state, scope, issue, &id)?;
    report.query = "dependency_witness".into();
    report.evidence_id = format!(
        "evidence-{}",
        fingerprint::id(&[&issue.id, &serde_json::to_string(&facts)?])
            .trim_start_matches("fnv1a64:")
    );
    report.facts = facts;
    report.queries.clear();
    report.rule_hints.clear();
    report.applicable_rule_planners.clear();
    report.does_not_prove = vec!["A retained candidate proves observed bytes, not a successful dependency match or authorization for a rule.".into()];
    report.next_step = "Trace the selected observed difference through Source and Target code. Recorded request header names come from authenticated input; public encrypted-header placeholders do not establish absence. Use narrower pointers for unavailable large values.".into();
    Ok(report)
}

fn observation(raw: Option<&[u8]>, pointer: &str) -> Value {
    let Some(raw) = raw else {
        return json!({"presence":"unavailable","reason":"selected document is unavailable"});
    };
    let Some(value) = crate::json_value::parse_with_limit(raw, 4 * 1024 * 1024) else {
        return json!({"presence":"unavailable","reason":"selected document is not supported JSON"});
    };
    let Some(value) = value.pointer(pointer) else {
        return json!({"presence":"missing"});
    };
    selected_observation(Some(value))
}

fn selected_observation(value: Option<&Value>) -> Value {
    let Some(value) = value else {
        return json!({"presence":"missing"});
    };
    let size = serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len());
    if size > 4096 {
        return json!({"presence":"unavailable","reason":"selected value exceeds 4096 bytes; choose a narrower pointer","bytes":size});
    }
    json!({"presence":"present","value":value})
}

fn source_event(directory: &Path, identity: &SourceIdentity, protocol: Protocol) -> Result<Value> {
    anyhow::ensure!(
        identity.exchange_id.is_some()
            || identity.connection_id.is_some() && identity.sequence.is_some(),
        "witness has no original Source exchange identity"
    );
    let event_type = match protocol {
        Protocol::Http => "http_exchange",
        Protocol::Mysql => "mysql_exchange",
        Protocol::Redis => "redis_exchange",
        Protocol::Memcached => "memcached_exchange",
    };
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
        if event["event_type"] != event_type {
            continue;
        }
        let matched = if let Some(id) = identity.exchange_id.as_ref() {
            event["id"] == *id
        } else {
            event["connection_id"].as_str() == identity.connection_id.as_deref()
                && event["sequence"]
                    .as_u64()
                    .or_else(|| event["query_sequence"].as_u64())
                    == identity.sequence
        };
        if matched {
            return Ok(event);
        }
    }
    anyhow::bail!("witness original Source event is unavailable")
}
