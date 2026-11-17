//! Full-recording format coverage, independent of API ownership. Source self
//! validation never counts as an independently observed Target witness.
use super::*;
use crate::policy::GLOBAL_JSON_ID;
use crate::value_contract::{global, json::Comparison, time::ClockPair};
mod headers;

struct CompareContext<'a> {
    host: &'a dyn crate::replay::policy::ValueRuleHost,
    clocks: AnchorClocks,
}

fn active(policy: &CompiledPolicy, selected: &BTreeSet<String>) -> bool {
    json_active(policy, selected)
        || selected.contains("global.mysql") && policy.mysql.is_some()
        || selected.contains("global.redis") && policy.redis.is_some()
        || selected.contains(crate::policy::GLOBAL_HTTP_ID) && policy.http.is_some()
}

fn json_active(policy: &CompiledPolicy, selected: &BTreeSet<String>) -> bool {
    policy.global_json.is_some()
        && (selected.contains(GLOBAL_JSON_ID)
            || selected.contains(crate::value_contract::time::automatic::RULE_ID))
}

pub(super) fn verify(
    root: &Path,
    bundle: &mut Bundle,
    previous: &CompiledPolicy,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    result: &mut Preflight,
) -> Result<()> {
    if !active(policy, selected) {
        return Ok(());
    }
    let service = value_service(policy)?;
    let manifest = bundle
        .replay
        .get("policy_witnesses")
        .cloned()
        .map(serde_json::from_value::<WitnessManifest>)
        .transpose()?;
    let private = if let Some(manifest) = manifest
        .as_ref()
        .filter(|manifest| manifest.complete && manifest.sealed)
    {
        let private = crate::policy_evidence::verify(&bundle.replay_path, manifest)?;
        for path in manifest.artifact_paths(&bundle.replay_path)? {
            bundle.freeze(&path)?;
        }
        Some(private)
    } else {
        None
    };
    let index = manifest
        .as_ref()
        .filter(|_| private.is_some())
        .map(WitnessManifest::source_index)
        .transpose()?;
    let mut candidates = candidate_pairs::Candidates::default();
    let inputs = super::input_retiming::Inputs::new(previous, policy);
    for (case, directory) in bundle.cases.clone() {
        let request = bundle.request(&directory.join("request.json"))?;
        let trace = bundle.dependency_path(&directory)?;
        bundle.freeze(&trace)?;
        if selected.contains(crate::policy::GLOBAL_HTTP_ID)
            && let Some(http) = &policy.http
        {
            headers::primary(bundle, &case, &directory, &request, http, result)?;
        }
        if json_active(policy, selected) {
            primary(
                root, bundle, &case, &directory, &request, policy, selected, result, &inputs,
            )
            .with_context(|| {
                format!("global format primary validation: case={case}, surface=api.response")
            })?;
        }
        visit(&trace, |event| {
            let clocks = source_clocks(timestamp(&request["timestamp"]), event);
            let Some(exchange) = recorded(event, &directory)? else {
                return Ok(());
            };
            for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
                let checked = compare_source_message(&exchange, surface, &service, clocks)
                    .with_context(|| format!("phase=source_self_validation, surface={surface:?}"))?;
                let relevant = record_source(&checked, selected, result)
                    .with_context(|| format!("phase=source_self_validation, surface={surface:?}"))?;
                if !relevant {
                    continue;
                }
                let Some(raw) = source_payload(event, surface, &directory)? else {
                    result.missing_target_witnesses += 1;
                    continue;
                };
                let identity = dependency::source_identity(&case, event);
                let mut found = false;
                if let (Some(index), Some(private), Some(identity)) =
                    (index.as_ref(), private.as_deref(), identity)
                {
                    for entry in index.for_source(surface, &identity) {
                        if entry.target_role() != TargetRole::IndependentTargetObservation
                            || !entry.has_target()
                            || entry.source_sha256()? != crate::policy_evidence::digest(&raw)
                        {
                            continue;
                        }
                        let witness = entry.expand()?;
                        let witness = witness.as_ref();
                        crate::policy_evidence::verify_case_clock(witness, &bundle.replay)?;
                        dependency::validate_metadata(witness, event)?;
                        let observed = witness.metadata.clocks.comparison();
                        ensure!(
                            observed.case.source == clocks.case.source
                                && observed
                                    .dependency
                                    .source
                                    .is_none_or(|time| Some(time) == clocks.dependency.source)
                                && observed
                                    .delivery
                                    .source
                                    .is_none_or(|time| Some(time) == clocks.delivery.source),
                            "global format witness Source anchors differ from immutable exchange"
                        );
                        let (retained, target) =
                            crate::policy_evidence::read(private, witness, &directory)?;
                        ensure!(
                            retained == raw,
                            "global format witness differs from immutable Source"
                        );
                        let target =
                            target.context("independent global format Target is unavailable")?;
                        let checked = compare_prepared(
                            event,
                            surface,
                            &raw,
                            &target,
                            &mut CompareContext {
                                host: &service,
                                clocks: observed,
                            },
                        )
                        .and_then(|comparison| valid_count(&comparison, selected))
                        .with_context(|| format!(
                            "phase=independent_target_validation, surface={surface:?}, witness_id={}, slot={:?}",
                            witness.id, witness.metadata.slot
                        ));
                        let count = if checked.is_err()
                            && surface == Surface::DependencyRequest
                            && inputs.precedes(witness)
                        {
                            // This is not validation under the proposed input.
                            // Preserve the protected observation as an explicit
                            // fresh-execution obligation, with no positive count.
                            super::input_retiming::Inputs::defer(&case, surface, Some(witness), result);
                            candidates.defer(witness)?;
                            0
                        } else if surface == Surface::DependencyRequest {
                            candidates.observe(witness, checked)?
                        } else {
                            match checked {
                                Ok(count) => count,
                                Err(_) => {
                                    result.defer_target_comparison(&case, surface, Some(&witness.id));
                                    0
                                }
                            }
                        };
                        if count > 0 {
                            found = true;
                            result.independent_target_validations += 1;
                        }
                    }
                }
                if !found {
                    result.missing_target_witnesses += 1;
                }

            }
            Ok(())
        }).with_context(|| format!("global format dependency validation: case={case}"))?;
    }
    candidates.finish(result);
    Ok(())
}

pub(super) fn global_trace(
    state: &RewriteState,
    bundle: &mut Bundle,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    result: &mut Preflight,
) -> Result<()> {
    if !active(policy, selected) {
        return Ok(());
    }
    let service = value_service(policy)?;
    let source = state
        .case_source
        .as_ref()
        .context("global formats require a Source recording")?;
    let (recording, _) = crate::dependency_index::recording_files(source)?;
    for kind in ["startup", "process", "shutdown", "unattributed"] {
        let path = recording.join(format!("indexes/{kind}-scope.json"));
        if !crate::dependency_index::scoped::exists(&path) {
            continue;
        }
        bundle.freeze(&path)?;
        visit(&path, |event| {
            let Some(exchange) = recorded(event, &recording)? else {
                return Ok(());
            };
            for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
                let comparison = compare_source_message(
                    &exchange,
                    surface,
                    &service,
                    source_clocks(None, event),
                )
                .with_context(|| format!("phase=source_self_validation, surface={surface:?}"))?;
                if record_source(&comparison, selected, result)
                    .with_context(|| format!("phase=source_self_validation, surface={surface:?}"))?
                {
                    // Background Source input is evidence of format only. It has no
                    // independent Target publication in the current API attempt.
                    result.missing_target_witnesses += 1;
                }
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn visit(path: &Path, mut visitor: impl FnMut(&Value) -> Result<()>) -> Result<()> {
    let mut reader = crate::dependency_index::RecordStream::open(path)?;
    while let Some((location, line)) = reader.next()? {
        ensure!(
            line.len() <= crate::dependency::http_limits::MAX_RECORD_BYTES,
            "global format record exceeds evidence bounds"
        );
        if !line.iter().all(u8::is_ascii_whitespace) {
            let event: Value = serde_json::from_slice(line)?;
            visitor(&event).with_context(|| format!(
                "global format trace={}, record={}, event_type={}, connection_id={}, sequence={}",
                path.display(), location.line,
                event["event_type"].as_str().unwrap_or("unknown"),
                event["connection_id"].as_str().unwrap_or("unknown"),
                event["sequence"].as_u64().or_else(|| event["query_sequence"].as_u64())
                    .map_or_else(|| "unknown".into(), |sequence| sequence.to_string()),
            ))?;
        }
    }
    Ok(())
}

fn source_clocks(case: Option<DateTime<Utc>>, event: &Value) -> AnchorClocks {
    let completed = timestamp(&event["timestamp"]);
    let started = crate::replay::dependency_started_at(event);
    let pair = |source| ClockPair {
        source,
        target: source,
    };
    AnchorClocks::for_request(pair(case), pair(started), pair(completed))
}

fn valid_count(comparison: &Comparison, selected: &BTreeSet<String>) -> Result<usize> {
    ensure!(
        comparison.passed(),
        "global format contract failed: {:?}",
        comparison.differences
    );
    Ok(comparison.evaluated.intersection(selected).count())
}

fn record_source(
    comparison: &Comparison,
    selected: &BTreeSet<String>,
    result: &mut Preflight,
) -> Result<bool> {
    if valid_count(comparison, selected)? == 0 {
        result.unavailable_source_values += 1;
        return Ok(false);
    }
    result.source_validations += 1;
    for id in comparison.evaluated.intersection(selected) {
        *result.rules.entry(id.clone()).or_default() += 1;
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)] // The selected evidence IDs remain separate from built-in policy.
fn primary(
    root: &Path,
    bundle: &mut Bundle,
    case: &str,
    directory: &Path,
    request: &Value,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    result: &mut Preflight,
    inputs: &super::input_retiming::Inputs,
) -> Result<()> {
    let plan = policy.global_json.as_ref().expect("selected global JSON");
    // Native owners compose into this comparison but their usage is recorded
    // by API preflight. Count global and built-in Source coverage once here.
    let selected = selected
        .iter()
        .filter(|id| {
            matches!(
                id.as_str(),
                GLOBAL_JSON_ID | crate::value_contract::time::automatic::RULE_ID
            )
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    let super::super::manifest::PrimaryResponse { source, target } =
        bundle.primary_response(case, directory)?;
    let source_pair =
        crate::primary_protocol::assertion::response_payload_pair(request, &source, None)?;
    let method = request["method"]
        .as_str()
        .context("global Source method unavailable")?;
    let uri: hyper::Uri = request["uri"]
        .as_str()
        .context("global Source URI unavailable")?
        .parse()?;
    let body = capture(&request["body"])
        .ok()
        .and_then(|bytes| crate::json_value::parse(&bytes));
    let native = crate::primary_protocol::assertion::native::selected(
        policy,
        method,
        uri.path(),
        body.as_ref(),
    )
    .into_iter()
    .filter(|rule| source_pair.body_available || !rule.rule.effect.is_response_body())
    .collect::<Vec<_>>();
    let context = crate::primary_protocol::assertion::native::NativeResponseContext::from_rules(
        &native, root, directory,
    )?;
    for (path, digest) in context.key_witnesses() {
        bundle.freeze(path)?;
        ensure!(
            bundle.artifacts[path].sha256 == *digest,
            "global API native input changed while freezing"
        );
    }
    context.ensure_current()?;

    let clocks = AnchorClocks::for_response(
        ClockPair {
            source: source_pair.request_times.source,
            target: source_pair.request_times.source,
        },
        ClockPair {
            source: source_pair.times.source,
            target: source_pair.times.source,
        },
    );
    let compare_body = |source: &[u8], target: &[u8], plan, clocks| {
        if context.is_empty() {
            compare_bytes(source, target, plan, clocks)
        } else if source == target {
            context.compare_encoded_source_coverage(source, &[], Some(plan), clocks)
        } else {
            context.compare_encoded_global(source, target, &[], Some(plan), clocks)
        }
    };
    let mut comparison = compare_body(&source_pair.source, &source_pair.source, plan, clocks)?;
    comparison.merge_and_validate(
        crate::primary_protocol::assertion::compare_interaction_global(
            source_pair.source_interaction.as_ref(),
            source_pair.source_interaction.as_ref(),
            Some(plan),
            ClockPair {
                source: source_pair.interaction_times.source,
                target: source_pair.interaction_times.source,
            },
            clocks.case,
            source_pair.max_interaction_message_bytes,
        )?,
    );
    let relevant = record_source(&comparison, &selected, result)
        .context("phase=source_self_validation, document=body_or_interaction")?;
    if !relevant {
        return Ok(());
    }
    let Some(target) = target else {
        result.missing_target_witnesses += 1;
        return Ok(());
    };
    let Some(pair) = super::response::target_pair(request, &source, &target, case, result)? else {
        return Ok(());
    };
    let clocks = AnchorClocks::for_response(pair.request_times, pair.times);
    let target_body = pair
        .target
        .as_deref()
        .context("global JSON Target body unavailable")?;
    let checked = (|| -> Result<usize> {
        let mut comparison = compare_body(&pair.source, target_body, plan, clocks)?;
        comparison.merge_and_validate(
            crate::primary_protocol::assertion::compare_interaction_global(
                pair.source_interaction.as_ref(),
                pair.target_interaction.as_ref(),
                Some(plan),
                pair.interaction_times,
                pair.request_times,
                pair.max_interaction_message_bytes,
            )?,
        );
        valid_count(&comparison, &selected)
    })();
    match checked {
        Ok(checked) if relevant || checked > 0 => result.independent_target_validations += 1,
        Ok(_) => {}
        Err(_) if inputs.precedes_response(pair.times) => {
            super::input_retiming::Inputs::defer(case, Surface::ApiResponse, None, result);
        }
        Err(_) => result.defer_target_comparison(case, Surface::ApiResponse, None),
    }
    Ok(())
}

#[cfg(test)]
fn compare(
    event: &Value,
    surface: Surface,
    source: &[u8],
    target: &[u8],
    policy: &CompiledPolicy,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    let service = value_service(policy)?;
    compare_prepared(
        event,
        surface,
        source,
        target,
        &mut CompareContext {
            host: &service,
            clocks,
        },
    )
}

fn compare_prepared(
    event: &Value,
    surface: Surface,
    source: &[u8],
    target: &[u8],
    context: &mut CompareContext<'_>,
) -> Result<Comparison> {
    use traffic_protocol::evidence::{MessageSide, SourceTiming};
    let providers = crate::protocols::default_providers();
    let owner = providers
        .event_provider(event)
        .context("native evidence owner is unavailable")?;
    let native = owner
        .provider
        .native_protocol()
        .context("native evidence capability is unavailable")?;
    let side = surface.dependency_side()?;
    let source = native.decode_evidence(event, source, side)?;
    let target = native.decode_evidence(event, target, side)?;
    for (evidence, request, delivered) in [
        (
            &source,
            context.clocks.dependency.source,
            context.clocks.delivery.source,
        ),
        (
            &target,
            context.clocks.dependency.target,
            context.clocks.delivery.target,
        ),
    ] {
        if let SourceTiming::Request {
            started_at,
            completed_at,
        } = evidence.timing
        {
            ensure!(
                started_at == request,
                "native evidence request clock differs from its witness"
            );
            if side == MessageSide::Response {
                ensure!(
                    completed_at == delivered,
                    "native evidence delivery clock differs from its witness"
                );
            }
        }
    }
    let service = context.host;
    let rules = providers.bindings().for_protocol(owner.kind.as_str());
    let request = crate::value_extensions::prepare_message_with_policy(
        source.request.as_ref(),
        &rules.request,
        service.document_policy(context.clocks),
    )?;
    let comparison =
        request.compare(target.request.as_ref(), context.clocks, service.metadata())?;
    if side == MessageSide::Response {
        ensure!(
            comparison.passed(),
            "response witness request context differs"
        );
        let source = source
            .response
            .context("Source response evidence is absent")?;
        let target = target
            .response
            .context("Target response evidence is absent")?;
        let mut clocks = context.clocks;
        clocks.observation = Some(clocks.delivery);
        let response = crate::value_extensions::prepare_message_with_policy(
            source.as_ref(),
            &rules.response,
            service.document_policy(clocks),
        )?;
        return response.compare(target.as_ref(), clocks, service.metadata());
    }
    Ok(comparison)
}

fn recorded(
    event: &Value,
    directory: &Path,
) -> Result<Option<traffic_protocol::connection::RecordedExchange>> {
    let providers = crate::protocols::default_providers();
    let Some(owner) = providers.event_provider(event) else {
        return Ok(None);
    };
    let Some(native) = owner.provider.native_protocol() else {
        return Ok(None);
    };
    native.recorded_exchange_with_secrets(
        event,
        &crate::request_headers::SourceSecrets::new(directory),
    )
}

fn source_payload(event: &Value, surface: Surface, directory: &Path) -> Result<Option<Vec<u8>>> {
    let providers = crate::protocols::default_providers();
    let owner = providers
        .event_provider(event)
        .context("Source evidence owner is unavailable")?;
    providers.evidence().source_payload(
        owner.kind.as_str(),
        event,
        surface.dependency_side()?,
        &crate::request_headers::SourceSecrets::new(directory),
    )
}

fn compare_source_message(
    exchange: &traffic_protocol::connection::RecordedExchange,
    surface: Surface,
    service: &dyn crate::replay::policy::ValueRuleHost,
    mut clocks: AnchorClocks,
) -> Result<Comparison> {
    let providers = crate::protocols::default_providers();
    let bindings = providers
        .bindings()
        .for_protocol(exchange.reference.protocol());
    let (message, bindings) = if surface == Surface::DependencyResponse {
        clocks.observation = Some(clocks.delivery);
        (
            exchange.response.as_ref() as &dyn traffic_protocol::message::ProtocolMessage,
            &bindings.response,
        )
    } else {
        (exchange.request.as_ref(), &bindings.request)
    };
    let prepared = crate::value_extensions::prepare_message_with_policy(
        message,
        bindings,
        service.document_policy(clocks),
    )?;
    prepared.compare(message, clocks, service.metadata())
}

fn value_service(policy: &CompiledPolicy) -> Result<crate::policy::runtime::RequestContracts> {
    let mut service = crate::policy::runtime::RequestContracts::default();
    service.configure_compiled(Some(std::sync::Arc::new(policy.clone())))?;
    Ok(service)
}

fn compare_bytes(
    source: &[u8],
    target: &[u8],
    plan: &crate::policy::CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    if source == target {
        global::compare_source_coverage(source, plan, &[], clocks)
    } else {
        global::compare(source, target, plan, &[], clocks)
    }
}

#[cfg(test)]
mod tests;
