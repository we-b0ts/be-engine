//! Exact selected arguments from independent unmatched requests need no invented Source pair.
use super::*;
use crate::policy::{Database, Protocol, Surface};
use crate::policy_evidence::{TargetRole, WitnessManifest};
use crate::rewrite::{RewriteContext, store::RewriteStore};

pub fn query_rewrite_redis_argument_for_scope(
    context: RewriteContext,
    scope: &RewriteWorkScope,
    case_id: &str,
    event_index: usize,
    argument_index: usize,
    pointer: Option<&str>,
) -> Result<RewriteEvidenceReport> {
    anyhow::ensure!(
        !case_id.is_empty() && case_id.len() <= 256 && argument_index < 16384,
        "Redis argument selector exceeds supported bounds"
    );
    if let Some(pointer) = pointer {
        anyhow::ensure!(
            pointer.starts_with('/') && pointer.len() <= 1024,
            "select a bounded non-root JSON pointer"
        );
    }
    let root = crate::e2e_run::resolve_project(&context.target_root)?.0;
    let state = RewriteStore::new(&root)?
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let RewriteWorkScope::Api { api } = scope;
    let state = super::super::api_selector::scoped(&state, api)?;
    let scope = super::super::api_selector::work_scope(&state, api);
    super::super::worker::ensure_scope_confirmed(
        &state,
        &scope,
        "querying protected Redis argument",
    )?;
    let issue = state
        .active_issue
        .as_ref()
        .context("API has no current issue")?;
    let context = e2e_context(&root, &state)?;
    let execution =
        crate::e2e_run::query_execution_context(context.clone(), group_id(&state)?, issue.attempt)?;
    let paths = crate::resolve_e2e_response_rule_evidence(context, group_id(&state)?)?;
    let bytes = std::fs::read(&paths.replay)?;
    let replay: Value = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        execution["session_id"].as_str().is_some()
            && execution["session_id"] == replay["session_id"],
        "Redis argument report differs from the selected attempt session"
    );
    let case = replay["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|case| case["case_id"] == case_id))
        .context("case is outside this API's current selected attempt")?;
    let directory = Path::new(
        case["case_dir"]
            .as_str()
            .context("case directory is unavailable")?,
    );
    let rows = replay["redis"]["unmatched"]
        .as_array()
        .context("no retained Redis unmatched requests")?;
    let mut matching = rows.iter().filter(|row| {
        row["case_id"] == case_id
            && row["target_event_index"].as_u64() == u64::try_from(event_index).ok()
    });
    let selected = matching
        .next()
        .context("unmatched Redis event is absent from this case")?;
    anyhow::ensure!(
        matching.next().is_none(),
        "unmatched Redis event identity is ambiguous"
    );
    let fingerprint = selected["request_fingerprint"]
        .as_str()
        .context("legacy event has no exact native request fingerprint")?;
    let manifest: WitnessManifest = serde_json::from_value(replay["policy_witnesses"].clone())?;
    anyhow::ensure!(
        manifest.complete && manifest.sealed,
        "protected Target publication is incomplete"
    );
    let private = crate::policy_evidence::verify(&paths.replay, &manifest)?;
    // verify loads and authenticates the graph through the manifest's shared storage.
    let graph = manifest
        .graph()
        .context("native Target observations are unavailable in this legacy attempt")?;
    let mut observation_ids = Vec::new();
    let mut observation_clocks = Vec::new();
    let mut observed = None;
    for (index, target) in graph.targets.iter().enumerate().filter(|(_, target)| {
        target.metadata.case_id == case_id
            && target.metadata.surface == Surface::DependencyRequest
            && target.metadata.role == TargetRole::IndependentTargetObservation
            && target.metadata.operation == selected["command"].as_str().unwrap_or_default()
    }) {
        let Some(resource) = target
            .metadata
            .resource
            .as_ref()
            .filter(|r| r.protocol == Protocol::Redis)
        else {
            continue;
        };
        let Some(Database::Index(database)) = resource.database.as_ref() else {
            continue;
        };
        let raw = crate::policy_evidence::read_target(&private, &manifest, index, directory)?;
        let args: Vec<Vec<u8>> = serde_json::from_slice(&raw)?;
        if ![2, 3].iter().any(|version| {
            crate::protocols::replay::redis_request_fingerprint(
                &resource.endpoint.host,
                resource.endpoint.port,
                *version,
                *database,
                resource.username.as_deref(),
                &target.metadata.operation,
                &args,
            ) == fingerprint
        }) {
            continue;
        }
        if let Some(previous) = &observed {
            anyhow::ensure!(
                previous == &args,
                "ambiguous protected Target request values"
            );
        } else {
            observed = Some(args);
        }
        observation_ids.push(target.id.clone());
        if observation_clocks.len() < 16 {
            observation_clocks.push(json!({"id":target.id,"clocks":target.metadata.clocks}));
        }
    }
    let args = observed.context("exact independent Target request payload is unavailable")?;
    let value = select_argument(args.get(argument_index).map(Vec::as_slice), pointer);
    let mut facts = json!({"attempt":issue.attempt,"recording_run_id":state.recording_run_id,"case_id":case_id,
        "target_event_index":event_index,"command":selected["command"],"request_fingerprint":fingerprint,
        "report_sha256":crate::policy_evidence::digest(&bytes),"target_role":"independent_target_observation",
        "argument_index":argument_index,"argument_count":args.len(),"argument_bytes":args.get(argument_index).map(Vec::len),
        "argument_sha256":args.get(argument_index).map(|bytes|crate::policy_evidence::digest(bytes)),"pointer":pointer,"target":value,
        "observation_count":observation_ids.len(),"target_observation_ids":observation_ids.iter().take(16).collect::<Vec<_>>(),
        "target_observations":observation_clocks,
        "omitted_observation_ids":observation_ids.len().saturating_sub(16),
        "association":"exact_native_request_fingerprint; identical requests may have multiple observations",
        "source_counterpart":"not_assumed"});
    facts["append_stream_progress"] = super::redis_stream_progress::facts(&replay, case_id);
    let mut report =
        super::report::selected(&root, &state, &scope, issue, "redis_target_argument", facts)?;
    report.does_not_prove=vec!["Observed Target bytes do not prove a Source counterpart, a successful match, task origin or permission for a rule.".into()];
    report.next_step="Trace the selected argument through Target and Source code. Select one argument and a narrower JSON pointer when a value exceeds 4096 bytes; no plaintext payload is written to artifacts.".into();
    Ok(report)
}

fn select_argument(raw: Option<&[u8]>, pointer: Option<&str>) -> Value {
    use base64::Engine as _;
    let Some(raw) = raw else {
        return json!({"presence":"missing"});
    };
    let (value, encoding) = if let Some(pointer) = pointer {
        let Some(value) = crate::json_value::parse(raw) else {
            return json!({"presence":"unavailable","reason":"selected argument is not complete JSON"});
        };
        let Some(value) = value.pointer(pointer) else {
            return json!({"presence":"missing"});
        };
        (value.clone(), "json")
    } else if let Ok(text) = std::str::from_utf8(raw) {
        (json!(text), "utf8")
    } else {
        (
            json!(base64::engine::general_purpose::STANDARD.encode(raw)),
            "base64",
        )
    };
    let size = serde_json::to_vec(&value).map_or(usize::MAX, |bytes| bytes.len());
    if size > 4096 {
        return json!({"presence":"unavailable","bytes":size,"reason":"selected value exceeds 4096 bytes; select a narrower JSON pointer"});
    }
    json!({"presence":"present","encoding":encoding,"value":value})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_argument_bounds_do_not_disclose_large_or_neighbor_values() {
        let bytes = serde_json::to_vec(
            &json!({"public":"ok","private":"secret".repeat(1000),"nullable":null}),
        )
        .unwrap();
        assert_eq!(
            select_argument(Some(&bytes), None)["presence"],
            "unavailable"
        );
        let selected = select_argument(Some(&bytes), Some("/public"));
        assert_eq!(selected["value"], "ok");
        assert!(!selected.to_string().contains("secret"));
        assert_eq!(
            select_argument(Some(&bytes), Some("/private"))["presence"],
            "unavailable"
        );
        assert_eq!(
            select_argument(Some(&bytes), Some("/nullable"))["value"],
            Value::Null
        );
        assert_eq!(
            select_argument(Some(&bytes), Some("/missing"))["presence"],
            "missing"
        );
        assert_eq!(select_argument(Some(&[255, 0]), None)["encoding"], "base64");
        assert_eq!(select_argument(None, None)["presence"], "missing");
    }
}
