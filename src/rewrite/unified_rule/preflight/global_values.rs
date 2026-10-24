//! Full-recording format coverage, independent of API ownership. Source self
//! validation never counts as an independently observed Target witness.
use super::*;
use crate::policy::{CompiledNativeRule, GLOBAL_JSON_ID};
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
    selected.contains(GLOBAL_JSON_ID) && policy.global_json.is_some()
        || selected.contains("global.mysql") && policy.mysql.is_some()
        || selected.contains("global.redis") && policy.redis.is_some()
        || selected.contains(crate::policy::GLOBAL_HTTP_ID) && policy.http.is_some()
}

pub(super) fn verify(
    root: &Path,
    bundle: &mut Bundle,
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
    let mut candidates = mysql_candidates::Candidates::default();
    for (case, directory) in bundle.cases.clone() {
        let request = bundle.request(&directory.join("request.json"))?;
        if selected.contains(crate::policy::GLOBAL_HTTP_ID)
            && let Some(http) = &policy.http
        {
            headers::primary(bundle, &case, &directory, &request, http, result)?;
        }
        if selected.contains(GLOBAL_JSON_ID) && policy.global_json.is_some() {
            primary(root, bundle, &case, &directory, &request, policy, result)?;
        }
        let trace = directory.join("dependencies.jsonl");
        bundle.freeze(&trace)?;
        let mut metadata = crate::replay::MysqlInferenceMetadata::default();
        visit(&trace, |event| metadata.observe_event(event))?;
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
                )?;
                let relevant = record_source(&checked, selected, result)?;
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
                        .and_then(|comparison| valid_count(&comparison, selected));
                        let count = if dependency::protocol(event) == Some(Protocol::Mysql)
                            && surface == Surface::DependencyRequest
                        {
                            candidates.observe(witness, checked)?
                        } else {
                            checked?
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
        })?;
    }
    candidates.finish()
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
    let path = recording.join("global-dependencies.jsonl");
    if !path.is_file() {
        return Ok(());
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
            )?;
            if record_source(&comparison, selected, result)? {
                // Background Source input is evidence of format only. It has no
                // independent Target publication in the current API attempt.
                result.missing_target_witnesses += 1;
            }
        }
        Ok(())
    })
}

fn visit(path: &Path, mut visitor: impl FnMut(&Value) -> Result<()>) -> Result<()> {
    ensure!(
        fs::metadata(path)?.len() <= 1024 * 1024 * 1024,
        "global format trace exceeds evidence bounds"
    );
    for line in BufReader::new(fs::File::open(path)?).lines() {
        let line = line?;
        ensure!(
            line.len() <= crate::dependency::http_limits::MAX_RECORD_BYTES,
            "global format record exceeds evidence bounds"
        );
        if !line.trim().is_empty() {
            visitor(&serde_json::from_str(&line)?)?;
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
    let started = timestamp(&event["request_started_at"]).or_else(|| {
        completed
            .zip(event["duration_ms"].as_u64())
            .and_then(|(time, duration)| {
                time.checked_sub_signed(chrono::TimeDelta::milliseconds(
                    i64::try_from(duration).ok()?,
                ))
            })
    });
    let pair = |source| ClockPair {
        source,
        target: source,
    };
    AnchorClocks {
        case: pair(case),
        dependency: pair(started),
        delivery: pair(completed),
    }
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

#[allow(clippy::too_many_arguments)]
fn primary(
    root: &Path,
    bundle: &mut Bundle,
    case: &str,
    directory: &Path,
    request: &Value,
    policy: &CompiledPolicy,
    result: &mut Preflight,
) -> Result<()> {
    let plan = policy.global_json.as_ref().expect("selected global JSON");
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

    let clocks = AnchorClocks {
        case: ClockPair {
            source: source_pair.times.source,
            target: source_pair.times.source,
        },
        dependency: ClockPair {
            source: source_pair.times.source,
            target: source_pair.times.source,
        },
        ..Default::default()
    };
    let compare_body = |source: &[u8], target: &[u8], clocks| {
        if context.is_empty() {
            global::compare(source, target, plan, &[], clocks)
        } else {
            context.compare_encoded_global(source, target, &[], Some(plan), clocks)
        }
    };
    let mut comparison = compare_body(&source_pair.source, &source_pair.source, clocks)?;
    comparison.merge_and_validate(crate::replay::compare_interaction_global(
        source_pair.source_interaction.as_ref(),
        source_pair.source_interaction.as_ref(),
        Some(plan),
        clocks.case,
    )?);
    let selected = BTreeSet::from([GLOBAL_JSON_ID.into()]);
    if !record_source(&comparison, &selected, result)? {
        return Ok(());
    }
    let Some(target) = target else {
        result.missing_target_witnesses += 1;
        return Ok(());
    };
    let pair = crate::replay::response_payload_pair(request, &source, Some(&target))?;
    let clocks = AnchorClocks {
        case: pair.times,
        dependency: pair.times,
        ..Default::default()
    };
    let mut checked = compare_body(
        &pair.source,
        pair.target
            .as_deref()
            .context("global JSON Target body unavailable")?,
        clocks,
    )?;
    checked.merge_and_validate(crate::replay::compare_interaction_global(
        pair.source_interaction.as_ref(),
        pair.target_interaction.as_ref(),
        Some(plan),
        pair.times,
    )?);
    valid_count(&checked, &selected)?;
    result.independent_target_validations += 1;
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
                let native = selected_native(context)?;
                crate::replay::http_validate_contract_witness(
                    source,
                    native_target,
                    surface,
                    &native,
                    clocks,
                )?;
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
        let mut checked = global::compare(source, target, plan, &[], clocks)?;
        checked.scope_schema_clocks(index);
        comparison.merge_and_validate(checked);
    }
    Ok(comparison)
}

fn selected_native<'a>(context: &CompareContext<'a>) -> Result<Vec<&'a CompiledNativeRule>> {
    let Some(request) = context.request else {
        return Ok(context
            .policy
            .native
            .iter()
            .filter(|rule| rule.rule.selector.api.is_none())
            .collect());
    };
    let method = request["method"]
        .as_str()
        .context("Source API method unavailable")?;
    let uri: hyper::Uri = request["uri"]
        .as_str()
        .context("Source API URI unavailable")?
        .parse()?;
    let body = capture(&request["body"])
        .ok()
        .and_then(|bytes| crate::json_value::parse(&bytes));
    Ok(crate::replay::native_response_selected(
        context.policy,
        method,
        uri.path(),
        body.as_ref(),
    ))
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
