//! Validate one published execution or a Source-only case batch without borrowing
//! another API's Target clocks or witness identities.
use super::*;

pub(super) fn verify(
    root: &Path,
    bundle: &mut Bundle,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    result: &mut Preflight,
) -> Result<()> {
    let mut candidates = candidate_pairs::Candidates::default();
    let manifest = bundle
        .replay
        .get("policy_witnesses")
        .cloned()
        .map(serde_json::from_value::<WitnessManifest>)
        .transpose()?;
    let private = if let Some(manifest) = &manifest {
        if manifest.complete && manifest.sealed {
            let path = crate::policy_evidence::verify(&bundle.replay_path, manifest)?;
            for artifact in manifest.artifact_paths(&bundle.replay_path)? {
                bundle.freeze(&artifact)?;
            }
            Some(path)
        } else {
            None
        }
    } else {
        None
    };
    let witness_index = manifest
        .as_ref()
        .filter(|_| private.is_some())
        .map(WitnessManifest::source_index)
        .transpose()?;
    for (case_id, directory) in bundle.cases.clone() {
        let request = bundle.request(&directory.join("request.json"))?;
        let method = request["method"]
            .as_str()
            .context("Source request method unavailable")?;
        let uri = request["uri"]
            .as_str()
            .context("Source request URI unavailable")?;
        let path = uri
            .parse::<hyper::Uri>()
            .context("invalid Source URI")?
            .path()
            .to_string();
        let source_body = capture(&request["body"])
            .ok()
            .and_then(|bytes| crate::json_value::parse(&bytes));
        let native_applicable =
            crate::replay::native_response_selected(policy, method, &path, source_body.as_ref());
        let native_response = native_applicable
            .iter()
            .copied()
            .filter(|rule| api::is_response(rule))
            .collect::<Vec<_>>();
        if native_response
            .iter()
            .any(|r| selected.contains(&r.rule.id))
        {
            api::verify(
                root,
                bundle,
                &case_id,
                &directory,
                &request,
                policy.global_json.as_ref(),
                &native_response,
                result,
            )?;
        }
        let dependency_path = bundle.dependency_path(&directory)?;
        bundle.freeze(&dependency_path)?;
        let dependency_bytes = crate::dependency_index::scoped::read_bytes(&dependency_path)?;
        ensure!(
            dependency_bytes.len() <= 1024 * 1024 * 1024,
            "Source trace inventory exceeds supported evidence bounds"
        );
        for line in BufReader::new(dependency_bytes.as_slice()).lines() {
            let line = line?;
            ensure!(
                line.len() <= crate::dependency::http_limits::MAX_RECORD_BYTES,
                "recorded exchange exceeds the supported evidence bound"
            );
            if line.trim().is_empty() {
                continue;
            }
            let event: Value = serde_json::from_str(&line)?;
            for surface in [Surface::DependencyRequest] {
                if dependency::protocol(&event) != Some(Protocol::Mysql) {
                    continue;
                }
                let mut native_sql = Vec::new();
                if surface == Surface::DependencyRequest
                    && dependency::protocol(&event) == Some(Protocol::Mysql)
                {
                    for rule in native_applicable
                        .iter()
                        .copied()
                        .filter(|rule| matches!(&rule.rule.effect, NativeEffect::MysqlValues(_)))
                    {
                        if dependency::selects_native_sql(rule, &event)? {
                            native_sql.push(rule);
                        }
                    }
                }
                if !native_sql.iter().any(|r| selected.contains(&r.rule.id)) {
                    continue;
                }
                ensure!(
                    event["replay_safe"] != false
                        && event["global_dependency_reason"].is_null()
                        && event["cache_snapshot_rule"].is_null(),
                    "value rule requires complete ordinary Case evidence; it does not authorize ownership or snapshots"
                );
                let raw = dependency::source_witness(surface, &event, &directory)?;
                let source_time = timestamp(&request["timestamp"]);
                let completed = timestamp(&event["timestamp"]);
                let started = crate::replay::dependency_started_at(&event);
                let source_clocks = AnchorClocks::for_request(
                    crate::value_contract::time::ClockPair {
                        source: source_time,
                        target: source_time,
                    },
                    crate::value_contract::time::ClockPair {
                        source: started,
                        target: started,
                    },
                    crate::value_contract::time::ClockPair {
                        source: completed,
                        target: completed,
                    },
                );
                let checked =
                    dependency::compare_source(surface, &event, &raw, &native_sql, source_clocks)?;
                if checked.is_empty() {
                    result.unavailable_source_values += 1;
                    continue;
                }
                result.source_validations += 1;
                for id in checked {
                    *result.rules.entry(id).or_default() += 1;
                }
                let Some(_manifest) = manifest.as_ref().filter(|_| private.is_some()) else {
                    result.missing_target_witnesses += 1;
                    continue;
                };
                let source_sha256 = crate::policy_evidence::digest(&raw);
                let mut found = false;
                let mut observations = BTreeSet::new();
                let http = dependency::protocol(&event) == Some(Protocol::Http);
                let identity = crate::policy_evidence::SourceIdentity {
                    case_id: case_id.clone(),
                    exchange_id: if http {
                        event["id"].as_str().map(str::to_owned)
                    } else {
                        None
                    },
                    connection_id: if http {
                        None
                    } else {
                        event["connection_id"].as_str().map(str::to_owned)
                    },
                    sequence: if http {
                        None
                    } else {
                        event[if dependency::protocol(&event) == Some(Protocol::Mysql) {
                            "query_sequence"
                        } else {
                            "sequence"
                        }]
                        .as_u64()
                    },
                };
                for entry in witness_index
                    .as_ref()
                    .unwrap()
                    .for_source(surface, &identity)
                {
                    let metadata = entry.metadata();
                    if entry.target_role() != TargetRole::IndependentTargetObservation {
                        continue;
                    }
                    let matches = metadata.surface == surface
                        && metadata.source.case_id == case_id
                        && (dependency::protocol(&event) == Some(Protocol::Http)
                            || event["connection_id"].is_string()
                                && if dependency::protocol(&event) == Some(Protocol::Mysql) {
                                    event["query_sequence"].is_u64()
                                } else {
                                    event["sequence"].is_u64()
                                })
                        && metadata.source.connection_id.as_deref()
                            == event["connection_id"].as_str()
                        && metadata.source.sequence
                            == if dependency::protocol(&event) == Some(Protocol::Mysql) {
                                event["query_sequence"].as_u64()
                            } else {
                                event["sequence"].as_u64()
                            }
                        && (dependency::protocol(&event) != Some(Protocol::Http)
                            || event["id"].is_string())
                        && metadata.source.exchange_id.as_deref()
                            == if dependency::protocol(&event) == Some(Protocol::Http) {
                                event["id"].as_str()
                            } else {
                                None
                            }
                        && entry.source_sha256()? == source_sha256
                        && entry.has_target();
                    if !matches {
                        continue;
                    }
                    let witness = entry.expand()?;
                    let witness = witness.as_ref();
                    crate::policy_evidence::verify_case_clock(witness, &bundle.replay)?;
                    dependency::validate_metadata(witness, &event)?;
                    let clocks = witness.metadata.clocks.comparison();
                    ensure!(
                        clocks.case.source == source_clocks.case.source
                            && clocks
                                .dependency
                                .source
                                .is_none_or(|time| Some(time) == source_clocks.dependency.source)
                            && clocks
                                .delivery
                                .source
                                .is_none_or(|time| Some(time) == source_clocks.delivery.source),
                        "protected witness Source anchors differ from the immutable exchange"
                    );
                    let (retained, target) = crate::policy_evidence::read(
                        private.as_ref().unwrap(),
                        witness,
                        &directory,
                    )?;
                    ensure!(
                        retained == raw,
                        "protected Source witness differs from immutable recording"
                    );
                    let target = target.context("Target payload witness is unavailable")?;
                    let stateful = native_sql.iter().filter(|rule|
                        matches!(&rule.rule.effect, NativeEffect::MysqlValues(effect) if !effect.params.is_empty()))
                        .map(|rule| rule.rule.id.clone()).collect::<BTreeSet<_>>();
                    if !stateful.is_empty() {
                        // Scalar masks prove neither a case binding nor its later references.
                        // Preserve the complete observation without claiming Target validation.
                        result.stateful_target_obligations.extend(stateful);
                        found = true;
                        continue;
                    }
                    let native_pair = if http {
                        &native_applicable
                    } else {
                        &native_sql
                    };
                    let normalized = if dependency::protocol(&event) == Some(Protocol::Mysql) {
                        crate::replay::mysql_normalize_identity_witnesses(
                            crate::replay::MysqlIdentityPreflight {
                                policy,
                                report: &bundle.replay,
                                case: &case_id,
                                request: &request,
                                dependencies: &dependency_bytes,
                                resource: witness
                                    .metadata
                                    .resource
                                    .as_ref()
                                    .context("SQL identity witness resource missing")?,
                                clocks,
                            },
                            &raw,
                            &target,
                        )?
                    } else {
                        None
                    };
                    let source_pair = normalized
                        .as_ref()
                        .map_or(raw.as_slice(), |n| n.source.as_slice());
                    let target_pair = normalized
                        .as_ref()
                        .map_or(target.as_slice(), |n| n.target.as_slice());
                    let comparison = dependency::compare_pair(
                        surface,
                        &event,
                        source_pair,
                        target_pair,
                            native_pair,
                        clocks,
                    )
                    .with_context(|| {
                        let rules = native_sql.iter().map(|r| r.rule.id.as_str()).collect::<Vec<_>>();
                        format!("dependency preflight failed for rules {rules:?}, Case {case_id}, Source connection {:?} sequence {:?}, Target observation {:?}",
                            witness.metadata.source.connection_id, witness.metadata.source.sequence,
                            witness.target_observation_id.as_deref().unwrap_or(&witness.id))
                    });
                    let evaluated = if surface == Surface::DependencyRequest
                        && dependency::protocol(&event) == Some(Protocol::Mysql)
                    {
                        candidates.observe(witness, comparison)?
                    } else {
                        comparison?
                    };
                    if evaluated == 0 {
                        continue;
                    }
                    if let Some(normalized) = normalized {
                        // The scalar/JSON comparison uses attested identity pairs;
                        // genuine Replay still re-establishes capture and use order.
                        result
                            .stateful_target_obligations
                            .extend(normalized.rule_ids);
                    }
                    found = true;
                    // One physical observation may be recorded once per SQL slot.
                    // Validate every protected envelope, then count the observation once.
                    if !observations.insert((
                        witness
                            .target_observation_id
                            .clone()
                            .or_else(|| witness.target_sha256.clone()),
                        serde_json::to_string(&witness.metadata.target_role)?,
                    )) {
                        continue;
                    }
                    match witness.metadata.target_role {
                        TargetRole::IndependentTargetObservation => {
                            result.independent_target_validations += 1
                        }
                        TargetRole::DerivedDelivery => result.derived_delivery_validations += 1,
                        TargetRole::DeliveredInput => {
                            anyhow::bail!(
                                "delivered input cannot substitute for Target comparison proof"
                            )
                        }
                        TargetRole::Unavailable => {
                            anyhow::bail!("Target witness has no independent or derived role")
                        }
                    }
                }
                if !found {
                    result.missing_target_witnesses += 1;
                }
            }
        }
    }
    candidates.finish()?;
    Ok(())
}
