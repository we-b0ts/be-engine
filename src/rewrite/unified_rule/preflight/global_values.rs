//! Full-recording format coverage, independent of API ownership. Source self
//! validation never counts as an independently observed Target witness.
use super::*;
use crate::policy::GLOBAL_JSON_ID;
use crate::value_contract::time_copies::TimeCopyStore;
use crate::value_contract::{global, json::Comparison, time::ClockPair};
mod headers;
mod redis;

struct CompareContext<'a> {
    policy: &'a CompiledPolicy,
    clocks: AnchorClocks,
    metadata: &'a crate::replay::MysqlInferenceMetadata,
    copies: Option<(&'a TimeCopyStore, &'a str)>,
    request: Option<&'a Value>,
    native_obligations: &'a mut BTreeSet<String>,
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
    // Case boundaries do not erase an input from the same protected Replay
    // session: application caches and in-flight work can carry it forward.
    // Collect first, independent of the case map's lexical iteration order.
    let mut inputs = super::input_retiming::Inputs::new(previous, policy);
    if inputs.enabled() {
        for (case, directory) in bundle.cases.clone() {
            let request = bundle.request(&directory.join("request.json"))?;
            let trace = bundle.dependency_path(&directory)?;
            bundle.freeze(&trace)?;
            let mut delivered = TimeCopyStore::default();
            delivered.begin_case(&case);
            visit(&trace, |event| {
                if matches!(
                    dependency::protocol(event),
                    Some(Protocol::Mysql | Protocol::Redis)
                ) && has_surface(event, Surface::DependencyResponse)
                    && let (Some(index), Some(private), Some(identity)) = (
                        index.as_ref(),
                        private.as_deref(),
                        time_copies::identity(&case, event),
                    )
                {
                    let raw =
                        dependency::source_witness(Surface::DependencyResponse, event, &directory)?;
                    time_copies::observe_global_with_retiming(
                        &mut delivered,
                        &case,
                        event,
                        &raw,
                        policy,
                        time_copies::ReadEvidence {
                            private,
                            directory: &directory,
                            report: &bundle.replay,
                            case_started: timestamp(&request["timestamp"]),
                            responses: index
                                .for_source(Surface::DependencyResponse, &identity)
                                .collect(),
                            requests: index
                                .for_source(Surface::DependencyRequest, &identity)
                                .collect(),
                        },
                        Some(&mut inputs),
                    )?;
                }
                Ok(())
            })?;
        }
    }
    for (case, directory) in bundle.cases.clone() {
        let request = bundle.request(&directory.join("request.json"))?;
        let trace = bundle.dependency_path(&directory)?;
        bundle.freeze(&trace)?;
        let mut metadata = crate::replay::MysqlInferenceMetadata::default();
        visit(&trace, |event| metadata.observe_event(event))?;
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
        let mut copies = TimeCopyStore::default();
        copies.begin_case(&case);
        visit(&trace, |event| {
            let clocks = source_clocks(timestamp(&request["timestamp"]), event);
            for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
                if dependency::protocol(event).is_none() || !has_surface(event, surface) {
                    continue;
                }
                let raw = dependency::source_witness(surface, event, &directory)?;
                let checked = compare_prepared(
                    event,
                    surface,
                    &raw,
                    &raw,
                    &mut CompareContext {
                        policy,
                        clocks,
                        metadata: &metadata,
                        copies: None,
                        request: Some(&request),
                        native_obligations: &mut result.stateful_target_obligations,
                    },
                ).with_context(|| format!("phase=source_self_validation, surface={surface:?}"))?;
                let relevant = record_source(&checked, selected, result)
                    .with_context(|| format!("phase=source_self_validation, surface={surface:?}"))?;
                if !relevant {
                    continue;
                }
                let identity = time_copies::identity(&case, event);
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
                        if dependency::protocol(event) == Some(Protocol::Redis)
                            && surface == Surface::DependencyRequest
                            && !redis::related_candidate(event, &raw, &target, policy, &request)?
                        {
                            continue;
                        }
                        if dependency::protocol(event) == Some(Protocol::Mysql)
                            && surface == Surface::DependencyRequest
                            && !crate::replay::mysql_request_candidates_related(
                                &raw, &target, observed,
                            )?
                        {
                            continue;
                        }
                        copies.set_lookup_clocks(observed.dependency);
                        let checked = compare_prepared(
                            event,
                            surface,
                            &raw,
                            &target,
                            &mut CompareContext {
                                policy,
                                clocks: observed,
                                metadata: &metadata,
                                copies: Some((&copies, &case)),
                                request: Some(&request),
                                native_obligations: &mut result.stateful_target_obligations,
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
                        } else if matches!(
                            dependency::protocol(event),
                            Some(Protocol::Mysql | Protocol::Redis)
                        )
                            && surface == Surface::DependencyRequest
                        {
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
                if surface == Surface::DependencyResponse
                    && let (Some(index), Some(private), Some(identity)) = (
                        index.as_ref(),
                        private.as_deref(),
                        time_copies::identity(&case, event),
                    )
                {
                    time_copies::observe_global(
                        &mut copies,
                        &case,
                        event,
                        &raw,
                        policy,
                        time_copies::ReadEvidence {
                            private,
                            directory: &directory,
                            report: &bundle.replay,
                            case_started: timestamp(&request["timestamp"]),
                            responses: index.for_source(surface, &identity).collect(),
                            requests: index
                                .for_source(Surface::DependencyRequest, &identity)
                                .collect(),
                        },
                    )?;
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
        let mut metadata = crate::replay::MysqlInferenceMetadata::default();
        visit(&path, |event| metadata.observe_event(event))?;
        visit(&path, |event| {
            if dependency::protocol(event).is_none() {
                return Ok(());
            }
            for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
                if !has_surface(event, surface) {
                    continue;
                }
                let raw = dependency::source_witness(surface, event, &recording)?;
                let comparison = compare_prepared(
                    event,
                    surface,
                    &raw,
                    &raw,
                    &mut CompareContext {
                        policy,
                        clocks: source_clocks(None, event),
                        metadata: &metadata,
                        copies: None,
                        request: None,
                        native_obligations: &mut result.stateful_target_obligations,
                    },
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

fn has_surface(event: &Value, surface: Surface) -> bool {
    if surface != Surface::DependencyResponse {
        return true;
    }
    match dependency::protocol(event) {
        Some(Protocol::Redis) => !event["response"].is_null(),
        Some(Protocol::Http) => {
            !event["response_body"].is_null()
                && event["outcome"]
                    .as_str()
                    .is_none_or(|outcome| outcome == "response")
        }
        Some(Protocol::Memcached) => event["no_response"] != true,
        _ => true,
    }
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
    let source_pair = crate::replay::response_payload_pair(request, &source, None)?;
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
    let native = crate::replay::native_response_selected(policy, method, uri.path(), body.as_ref())
        .into_iter()
        .filter(|rule| source_pair.body_available || !rule.rule.effect.is_response_body())
        .collect::<Vec<_>>();
    let context = crate::replay::NativeResponseContext::from_rules(&native, root, directory)?;
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
    comparison.merge_and_validate(crate::replay::compare_interaction_global(
        source_pair.source_interaction.as_ref(),
        source_pair.source_interaction.as_ref(),
        Some(plan),
        ClockPair {
            source: source_pair.interaction_times.source,
            target: source_pair.interaction_times.source,
        },
        clocks.case,
        source_pair.max_interaction_message_bytes,
    )?);
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
        comparison.merge_and_validate(crate::replay::compare_interaction_global(
            pair.source_interaction.as_ref(),
            pair.target_interaction.as_ref(),
            Some(plan),
            pair.interaction_times,
            pair.request_times,
            pair.max_interaction_message_bytes,
        )?);
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
    compare_prepared(
        event,
        surface,
        source,
        target,
        &mut CompareContext {
            policy,
            clocks,
            metadata: &crate::replay::MysqlInferenceMetadata::default(),
            copies: None,
            request: None,
            native_obligations: &mut BTreeSet::new(),
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
    let policy = context.policy;
    let clocks = context.clocks;
    if dependency::protocol(event) == Some(Protocol::Mysql) {
        if source == target && context.copies.is_none() {
            return crate::replay::mysql_validate_global_source_witness(
                event["database"].as_str(),
                source,
                surface,
                policy,
                clocks,
                &observed_resource(event)?,
                context.metadata,
            );
        }
        if let Some((store, case)) = context.copies {
            return crate::replay::mysql_validate_global_witness_with_time_copies(
                event["database"].as_str(),
                source,
                target,
                surface,
                policy,
                clocks,
                &observed_resource(event)?,
                store,
                case,
                context.metadata,
            );
        }
        let store = TimeCopyStore::default();
        return crate::replay::mysql_validate_global_witness_with_time_copies(
            event["database"].as_str(),
            source,
            target,
            surface,
            policy,
            clocks,
            &observed_resource(event)?,
            &store,
            "",
            context.metadata,
        );
    }
    if dependency::protocol(event) == Some(Protocol::Redis) {
        if policy.global_json.is_some() || policy.redis.is_some() {
            return redis::compare(event, surface, source, target, context);
        }
        return Ok(Comparison::default());
    }
    let (mut comparison, normalized_headers) = if dependency::protocol(event)
        == Some(Protocol::Http)
        && let Some(http) = &policy.http
    {
        let (comparison, target) = headers::dependency(source, target, surface, http, clocks)?;
        (comparison, Some(target))
    } else {
        (Comparison::default(), None)
    };
    let native_target = normalized_headers.as_deref().unwrap_or(target);
    let before = dependency::values(surface, event, source)?;
    let after = dependency::values(surface, event, target)?;
    // Source self-validation checks only immutable content. Paired observations
    // additionally prove the carrier's endpoint, headers, options and clocks.
    if source != target
        || clocks.dependency.source != clocks.dependency.target
        || clocks.delivery.source != clocks.delivery.target
    {
        match dependency::protocol(event) {
            Some(Protocol::Http) => {
                crate::replay::http_validate_witness(source, native_target, surface, clocks)?;
            }
            Some(Protocol::Memcached) => {
                let keys = before
                    .iter()
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                crate::replay::memcached_validate_witness(source, target, surface, &keys, clocks)?;
            }
            _ => {}
        }
    }
    ensure!(
        before.len() == after.len(),
        "global JSON dependency value inventory changed"
    );
    if dependency::protocol(event) == Some(Protocol::Http)
        && crate::replay::http_multipart_witness_matches(source, native_target, surface)?
    {
        return Ok(comparison);
    }
    let Some(plan) = &policy.global_json else {
        return Ok(comparison);
    };
    for (index, ((key, source), (other, target))) in before.iter().zip(&after).enumerate() {
        ensure!(key == other, "global JSON dependency position changed");
        if dependency::protocol(event) == Some(Protocol::Memcached)
            && surface == Surface::DependencyRequest
            && !event["command"].as_str().is_some_and(|command| {
                matches!(
                    command.to_ascii_lowercase().as_str(),
                    "set" | "add" | "replace" | "cas"
                )
            })
        {
            ensure!(source == target, "Memcached fragments remain exact");
            continue;
        }
        let mut checked = compare_bytes(source, target, plan, clocks)?;
        checked.scope_schema_clocks(index);
        comparison.merge_and_validate(checked);
    }
    Ok(comparison)
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

fn observed_resource(event: &Value) -> Result<crate::policy::Resource> {
    let protocol =
        dependency::protocol(event).context("global format resource protocol unavailable")?;
    Ok(crate::policy::Resource {
        protocol,
        endpoint: crate::policy::Endpoint {
            host: event["target_host"]
                .as_str()
                .context("global format resource endpoint unavailable")?
                .into(),
            port: u16::try_from(
                event["target_port"]
                    .as_u64()
                    .context("global format resource port unavailable")?,
            )?,
        },
        database: match protocol {
            Protocol::Redis => event["database"]
                .as_i64()
                .map(crate::policy::Database::Index),
            Protocol::Mysql => event["database"]
                .as_str()
                .map(|name| crate::policy::Database::Name(name.into())),
            _ => None,
        },
        username: event["username"].as_str().map(str::to_owned),
    })
}

#[cfg(test)]
mod tests;
