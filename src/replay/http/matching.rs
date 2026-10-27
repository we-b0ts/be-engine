//! Case-owned HTTP request selection and atomic normalization.
use super::*;
impl ReplayState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn match_http_request(
        &mut self,
        scheme: HttpReplayScheme,
        target: &TargetKey,
        method: &Method,
        uri: &Uri,
        host: Option<&str>,
        body: &[u8],
        headers: &HeaderSnapshot,
        request_started_at: chrono::DateTime<Utc>,
    ) -> std::result::Result<RecordedHttpExchange, HttpReplayMatchError> {
        let active_case_id = self.active_case_id.clone();
        let mut observation_id = Some(uuid::Uuid::new_v4());
        if let Some(host) = host
            && !host_matches_target(host, target)
        {
            let reason = format!(
                "HTTP Host header does not match replay target {}",
                target.host
            );
            self.record_unmatched_http(scheme, target, method, uri, reason.clone());
            return Err(HttpReplayMatchError::BadGateway(reason));
        }

        if let (Some(policy), Some(case)) = (&self.replay_policy, active_case_id.as_deref()) {
            match contracts::record_target(
                policy,
                case,
                &contracts::RequestView {
                    observation_id,
                    scheme,
                    target,
                    method,
                    uri,
                    headers,
                    body,
                    started_at: request_started_at,
                },
            ) {
                Ok(crate::policy_evidence::ObservationRetention::Unavailable) => {
                    observation_id = None
                }
                Ok(crate::policy_evidence::ObservationRetention::Retained) => {}
                Err(error) => {
                    tracing::warn!(error = %error, "HTTP Target observation unavailable");
                    // Global and shared-origin candidates keep native matching.
                    // Keep the identity: a Case candidate must still associate
                    // its retained Target before any rule comparison succeeds.
                }
            }
        }
        let mut matching_index = None;
        let mut matching_policy_decision = DependencyRuleDecision::default();
        let mut matching_dynamic_decision =
            crate::replay::policy::dynamic_values::DynamicDecision::default();
        let mut matching_request_decision = None;
        let mut matching_multipart = false;
        let mut closest_mismatch = None;
        let mut body_comparisons = Vec::new();
        let mut omitted_body_comparisons = 0;
        let mut target_fingerprint = None;
        'sources: for (allow_pre_match, source) in [
            (false, ReplaySource::Case),
            (false, ReplaySource::Global),
            (true, ReplaySource::Case),
        ] {
            if allow_pre_match
                && !self
                    .replay_policy
                    .as_ref()
                    .is_some_and(|p| p.request_contracts.pre_match_enabled())
            {
                break;
            }
            for (index, exchange) in self.http_exchanges.iter().enumerate() {
                if !exchange.status.is_available() && !exchange.is_repeatable_preflight_probe()
                    || exchange.source != source
                    || !active_http_case_matches(active_case_id.as_deref(), exchange)
                    || exchange.identity.scheme != scheme
                    || exchange.identity.target != *target
                {
                    continue;
                }
                if exchange.record.method.eq_ignore_ascii_case(method.as_str())
                    && uri_path_only(&exchange.record.uri) == uri.path()
                    && let Some(policy) = &self.replay_policy
                    && let Err(error) = contracts::record_request(
                        policy,
                        exchange,
                        &contracts::RequestView {
                            observation_id,
                            scheme,
                            target,
                            method,
                            uri,
                            headers,
                            body,
                            started_at: request_started_at,
                        },
                    )
                {
                    closest_mismatch.get_or_insert_with(|| {
                        format!("HTTP request witness unavailable: {error:#}")
                    });
                    continue;
                }
                if let Some(origin) = &exchange.shared_origin
                    && &origin.request_fingerprint
                        != target_fingerprint.get_or_insert_with(|| {
                            cross_case::request_fingerprint(&uri.to_string(), body, headers)
                        })
                {
                    closest_mismatch.get_or_insert_with(|| {
                        "cross-case request query, body or identity headers differ".to_string()
                    });
                    continue;
                }
                let normalized = if exchange.source == ReplaySource::Case
                    && exchange.shared_origin.is_none()
                {
                    self.replay_policy.as_ref().and_then(|policy| {
                        if !policy.dynamic_values.enabled() {
                            return None;
                        }
                        decode_body(&exchange.record.request_body)
                            .ok()
                            .and_then(|source_body| {
                                policy.dynamic_values.http(
                                    exchange.case_id.as_deref(),
                                    target,
                                    method.as_str(),
                                    crate::replay::policy::dynamic_values::HttpInput {
                                        uri: &exchange.record.uri,
                                        body: &source_body,
                                        request_started_at: request_headers::time_reference::source(
                                            &exchange.record,
                                        ),
                                    },
                                    crate::replay::policy::dynamic_values::HttpInput {
                                        uri: &uri.to_string(),
                                        body,
                                        request_started_at: Some(request_started_at),
                                    },
                                )
                            })
                    })
                } else {
                    None
                };
                let normalized = match normalized {
                    Some(Ok(value)) => Some(value),
                    Some(Err(_)) => {
                        closest_mismatch.get_or_insert(
                            "HTTP dynamic identity did not match its case binding".into(),
                        );
                        continue;
                    }
                    None => None,
                };
                let normalized_exchange = normalized.as_ref().map(|value| {
                    let mut copy = exchange.clone();
                    copy.record.uri = value.source_uri.clone();
                    copy.record.request_body.encoding = "base64".into();
                    copy.record.request_body.data = STANDARD.encode(&value.source_body);
                    copy
                });
                let exchange = normalized_exchange.as_ref().unwrap_or(exchange);
                let uri = normalized.as_ref().map_or(uri, |value| &value.actual_uri);
                let body = normalized
                    .as_ref()
                    .map_or(body, |value| value.actual_body.as_slice());
                let mut policy_decision = if exchange.shared_origin.is_some() {
                    DependencyRuleDecision::default()
                } else if let Some(policy) = &self.replay_policy {
                    match policy.preview_http(
                        &HttpPolicyContext {
                            request_times: crate::replay::assertion::RequestTimes {
                                source: request_headers::time_reference::source(&exchange.record),
                                target: Some(request_started_at),
                            },
                            case_id: active_case_id.as_deref(),
                            target,
                            method: method.as_str(),
                            recorded_uri: &exchange.record.uri,
                            actual_uri: &uri.to_string(),
                        },
                        Utc::now(),
                    ) {
                        Ok(decision) => decision,
                        Err(reason) => {
                            closest_mismatch.get_or_insert(reason);
                            continue;
                        }
                    }
                } else {
                    DependencyRuleDecision::default()
                };

                let mut ignored_query_params = self.http_ignore_query_params.clone();
                ignored_query_params.extend(policy_decision.dynamic_query_params.iter().cloned());
                if exchange.shared_origin.is_some() {
                    ignored_query_params.clear();
                }
                let (mut mismatch, multipart_source_body) =
                    http_request_comparison(exchange, method, uri, body, &ignored_query_params);

                let mut declared_headers = None;
                if (mismatch.is_none()
                    || mismatch.as_deref()
                        == Some("HTTP request body did not match the recorded body"))
                    && let Some(policy) = &self.replay_policy
                    && let Some(compared) = request_headers::preview_global(
                        &policy.request_contracts,
                        active_case_id.as_deref().or(exchange.case_id.as_deref()),
                        &exchange.record.request_headers,
                        headers,
                        request_headers::time_reference::source(&exchange.record),
                        request_started_at,
                    )
                {
                    match compared {
                        Ok((decision, headers)) => {
                            policy_decision.value_contracts.push(decision);
                            declared_headers = Some(headers);
                        }
                        Err(error) => {
                            mismatch = Some(format!("HTTP header value contract failed: {error:#}"))
                        }
                    }
                }
                let headers = declared_headers.as_ref().unwrap_or(headers);
                let mut request_decision = None;
                let mut body_comparison = None;
                let multipart = if mismatch.is_none()
                    || mismatch.as_deref()
                        == Some("HTTP request body did not match the recorded body")
                {
                    multipart_source_body.and_then(|source_body| {
                        multipart::preview(
                            &source_body,
                            &exchange.record.request_headers,
                            body,
                            headers,
                        )
                    })
                } else {
                    None
                };
                let multipart_selected = multipart.is_some();
                let mut multipart_matched = false;
                if let Some(result) = multipart {
                    match result {
                        Ok(()) => {
                            mismatch = None;
                            multipart_matched = true;
                        }
                        Err(_) => mismatch = Some("HTTP multipart request differs".into()),
                    }
                }
                if !multipart_selected
                    && (mismatch.is_none()
                        || mismatch.as_deref()
                            == Some("HTTP request body did not match the recorded body"))
                    && let Some(policy) = &self.replay_policy
                    && let Some(result) = contracts::preview_request(
                        policy,
                        exchange,
                        active_case_id.as_deref(),
                        &contracts::RequestView {
                            observation_id,
                            scheme,
                            target,
                            method,
                            uri,
                            headers,
                            body,
                            started_at: request_started_at,
                        },
                        &policy_decision.dynamic_query_params,
                        &mut body_comparison,
                        allow_pre_match,
                    )
                {
                    match result {
                        Ok(decision) => {
                            mismatch = None;
                            policy_decision.value_contracts.push(decision);
                        }
                        Err(error) => {
                            mismatch = Some(format!("HTTP body value contract failed: {error:#}"))
                        }
                    }
                }
                if let Some(comparison) = body_comparison {
                    if body_comparisons.len() < 64 {
                        body_comparisons.push(comparison);
                    } else {
                        omitted_body_comparisons += 1;
                    }
                }
                if exchange.source == ReplaySource::Case
                    && exchange.shared_origin.is_none()
                    && (mismatch.is_none()
                        || mismatch.as_deref()
                            == Some("HTTP request body did not match the recorded body"))
                    && let (Some(policy), Some(case), Ok(source_body)) = (
                        &self.replay_policy,
                        active_case_id.as_deref(),
                        decode_body(&exchange.record.request_body),
                    )
                {
                    if let Some(result) = policy.request_contracts.preview_multipart(
                        case,
                        target,
                        method.as_str(),
                        uri.path(),
                        &source_body,
                        &exchange.record.request_headers,
                        body,
                        headers,
                    ) {
                        match result {
                            Ok(decision) => {
                                mismatch = None;
                                request_decision = Some(decision);
                            }
                            Err(_) => {
                                mismatch = Some("HTTP multipart request contract differs".into())
                            }
                        }
                    }
                    if mismatch.is_some() {
                        let mut source_headers = exchange.record.request_headers.clone();
                        let mut actual_headers = headers.clone();
                        source_headers.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
                        actual_headers.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
                        if request_headers::exact_contract_match(&source_headers, &actual_headers) {
                            policy.request_contracts.observe_http(
                                case,
                                target,
                                method.as_str(),
                                &exchange.record.uri,
                                &source_body,
                                &exchange.record.request_headers,
                                body,
                                headers,
                                crate::replay::assertion::RequestTimes {
                                    source: request_headers::time_reference::source(
                                        &exchange.record,
                                    ),
                                    target: Some(request_started_at),
                                },
                            );
                        }
                    }
                }
                if let Some(reason) = mismatch {
                    if exchange.source == ReplaySource::Case
                        && exchange.shared_origin.is_none()
                        && exchange.record.method.eq_ignore_ascii_case(method.as_str())
                        && let (Some(policy), Some(case), Ok(source_body)) = (
                            &self.replay_policy,
                            active_case_id.as_deref(),
                            decode_body(&exchange.record.request_body),
                        )
                    {
                        policy.dynamic_values.observe_http_path(
                            case,
                            target,
                            method.as_str(),
                            crate::replay::policy::dynamic_values::HttpInput {
                                uri: &exchange.record.uri,
                                body: &source_body,
                                request_started_at: request_headers::time_reference::source(
                                    &exchange.record,
                                ),
                            },
                            crate::replay::policy::dynamic_values::HttpInput {
                                uri: &uri.to_string(),
                                body,
                                request_started_at: Some(request_started_at),
                            },
                        );
                    }
                    if reason == "HTTP request body did not match the recorded body"
                        && exchange.source == ReplaySource::Case
                        && exchange.shared_origin.is_none()
                        && request_headers::exact_contract_match(
                            &exchange.record.request_headers,
                            headers,
                        )
                        && let (Some(policy), Some(case), Ok(source_body)) = (
                            &self.replay_policy,
                            active_case_id.as_deref(),
                            decode_body(&exchange.record.request_body),
                        )
                    {
                        policy.dynamic_values.observe_http(
                            case,
                            target,
                            method.as_str(),
                            uri.path(),
                            &source_body,
                            body,
                        );
                    }
                    closest_mismatch.get_or_insert(reason);
                    continue;
                }
                if let Some(policy) = &self.replay_policy {
                    let mut combined = crate::replay::policy::request_contract::Decision::default();
                    let checked = (|| -> Result<()> {
                        for identity in policy_decision.identity_proposals().chain(
                            request_decision
                                .iter()
                                .filter_map(|decision| decision.identity.as_ref()),
                        ) {
                            policy
                                .request_contracts
                                .merge_identity_decision(&mut combined, identity.clone())?;
                        }
                        if let (Some(case), Some(normalized)) =
                            (active_case_id.as_deref(), normalized.as_ref())
                        {
                            policy.dynamic_values.join_identities(
                                case,
                                &normalized.decision,
                                &mut combined,
                            )?;
                        }
                        Ok(())
                    })();
                    if checked.is_err() {
                        closest_mismatch.get_or_insert(
                            "HTTP header/body identity correspondence changed".into(),
                        );
                        continue;
                    }
                }
                matching_request_decision = request_decision;
                matching_multipart = multipart_matched;
                matching_index = Some(index);
                matching_policy_decision = policy_decision;
                if let Some(normalized) = normalized {
                    matching_dynamic_decision = normalized.decision;
                }
                break 'sources;
            }
        }
        let Some(index) = matching_index else {
            if self.claim_http_blackhole(target, method, uri) {
                return Err(HttpReplayMatchError::Blackhole);
            }
            let reason = closest_mismatch.unwrap_or_else(|| {
                "no recorded HTTP exchange matched the active case and target".to_string()
            });
            let evidence = unordered::evidence::capture(self, scheme, target, method, uri, body);
            self.record_unmatched_http(scheme, target, method, uri, reason.clone());
            self.http_events
                .unmatched
                .last_mut()
                .unwrap()
                .unordered_json = Some(evidence);
            self.http_events
                .unmatched
                .last_mut()
                .unwrap()
                .target_observation_id = observation_id.map(|id| {
                crate::policy_evidence::target_observation_id(
                    &id.to_string(),
                    crate::policy::Surface::DependencyRequest,
                    crate::policy_evidence::TargetRole::IndependentTargetObservation,
                )
            });
            self.http_events
                .unmatched
                .last_mut()
                .unwrap()
                .body_comparisons = body_comparisons;
            self.http_events
                .unmatched
                .last_mut()
                .unwrap()
                .omitted_body_comparisons = omitted_body_comparisons;
            return Err(HttpReplayMatchError::BadGateway(reason));
        };
        let mut exchange = self.http_exchanges[index].clone();
        if let Err(error) = exchange.record.materialize_response() {
            let reason = format!("HTTP response evidence unavailable: {error:#}");
            self.record_unmatched_http(scheme, target, method, uri, reason.clone());
            return Err(HttpReplayMatchError::BadGateway(reason));
        }
        let lifecycle_cleanup = active_case_id.as_deref().and_then(|case| {
            let id = exchange.record.id.as_deref()?.parse().ok()?;
            self.async_cleanup_gate(
                case,
                crate::replay::control::dependency_tail::RecordedReference::Http {
                    exchange_id: id,
                },
            )
        });
        let recorded_upstream_failure = upstream_failure::is_recorded(&exchange.record);
        if lifecycle_cleanup.is_none()
            && !recorded_upstream_failure
            && !exchange.record.outcome.is_client_terminated()
            && !exchange.record.outcome.is_server_terminated()
            && (exchange.record.error.is_some() || exchange.record.response_status.is_none())
        {
            self.http_exchanges[index].status = crate::replay::ReplayExchangeStatus::Consumed;
            self.refresh_http_global_report(index);
            let reason = "recorded HTTP exchange contains an upstream error that replay v1 cannot synthesize"
                .to_string();
            if let Some(case_id) = &exchange.case_id {
                self.http_events.dirty_case_ids.insert(case_id.clone());
            }
            self.http_events.unsupported.push(HttpRequestReport {
                case_id: exchange.case_id,
                scheme,
                target: target.clone(),
                method: method.to_string(),
                uri: uri_path_only(&uri.to_string()),
                reason: reason.clone(),
                target_observation_id: None,
                body_comparisons: Vec::new(),
                omitted_body_comparisons: 0,
                request_fingerprint: None,
                unordered_json: None,
            });
            return Err(HttpReplayMatchError::BadGateway(reason));
        }

        if (lifecycle_cleanup.is_none() || exchange.record.response_stream.is_some())
            && let Some(policy) = &self.replay_policy
        {
            let mut captured = crate::replay::policy::request_contract::Decision::default();
            if let Some(case) = active_case_id.as_deref() {
                policy
                    .dynamic_values
                    .join_identities(case, &matching_dynamic_decision, &mut captured)
                    .map_err(|error| HttpReplayMatchError::BadGateway(error.to_string()))?;
            }
            let owner = policy
                .request_contracts
                .with_identity_proposals(
                    matching_policy_decision
                        .identity_proposals()
                        .chain(
                            matching_request_decision
                                .iter()
                                .filter_map(|decision| decision.identity.as_ref()),
                        )
                        .chain(captured.identity.iter()),
                )
                .map_err(|error| HttpReplayMatchError::BadGateway(error.to_string()))?;
            match contracts::materialize_response(
                &owner,
                &mut exchange,
                active_case_id.as_deref(),
                request_started_at,
            ) {
                Ok(decision) => matching_policy_decision
                    .value_contracts
                    .extend(decision.value_contracts),
                Err(error) => {
                    let reason = format!("HTTP response value contract failed: {error:#}");
                    self.record_unmatched_http(scheme, target, method, uri, reason.clone());
                    return Err(HttpReplayMatchError::BadGateway(reason));
                }
            }
        }
        let mut audited_headers = headers.clone();
        if matching_multipart || matching_request_decision.is_some() {
            audited_headers.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
            for (name, values) in &exchange.record.request_headers {
                if name.eq_ignore_ascii_case("content-type") {
                    audited_headers.insert(name.clone(), values.clone());
                }
            }
        }
        if let Some(policy) = &mut self.replay_policy {
            let mut captures = crate::replay::policy::request_contract::Decision::default();
            if let Some(case) = active_case_id.as_deref() {
                policy
                    .dynamic_values
                    .join_identities(case, &matching_dynamic_decision, &mut captures)
                    .map_err(|error| HttpReplayMatchError::BadGateway(error.to_string()))?;
            }
            matching_policy_decision.value_contracts.push(captures);
            matching_policy_decision
                .value_contracts
                .extend(matching_request_decision.take());
            policy
                .commit(active_case_id.as_deref(), matching_policy_decision)
                .map_err(|error| HttpReplayMatchError::BadGateway(error.to_string()))?;
            if let Some(case) = active_case_id.as_deref() {
                policy
                    .dynamic_values
                    .commit_after_identities(case, matching_dynamic_decision);
            }
        }
        self.audit_http_request_headers(&exchange, index, &audited_headers, request_started_at);
        let detail = MatchedHttpExchangeReport {
            case_id: active_case_id.clone(),
            shared_origin: exchange.shared_origin.clone(),
            source: exchange.source,
            index,
            scheme,
            target: target.clone(),
            method: method.to_string(),
            uri: uri_path_only(&uri.to_string()),
            status: exchange.record.response_status,
            outcome: exchange.record.outcome,
            target_event_index: 0,
        };
        if let Some(gate) = lifecycle_cleanup {
            // Source stopped before receiving a response. Retain the original
            // claimed request until the runner stops Target; never synthesize
            // the proxy's post-stop 502 as a business dependency response.
            self.http_exchanges[index].status =
                crate::replay::ReplayExchangeStatus::AwaitingClientTermination;
            if exchange.record.response_stream.is_some() {
                self.http_exchanges[index].status = crate::replay::ReplayExchangeStatus::Responding;
                exchange.record.lifecycle_stop = Some(gate);
                exchange.record.stream_delivery = Some(detail);
                return Ok(exchange.record);
            }
            return Err(HttpReplayMatchError::ClientTerminated(Box::new(
                termination::PendingHttpTermination::for_lifecycle_stop(
                    detail,
                    &exchange.record,
                    gate,
                ),
            )));
        }
        if exchange.record.outcome.is_server_terminated()
            && exchange.record.response_stream.is_none()
        {
            self.http_exchanges[index].status = crate::replay::ReplayExchangeStatus::Responding;
            return Err(HttpReplayMatchError::ServerTerminated(Box::new(
                termination::PendingHttpTermination::new(detail, &exchange.record),
            )));
        }
        if exchange.record.outcome.is_client_terminated()
            && exchange.record.response_stream.is_none()
        {
            self.http_exchanges[index].status =
                crate::replay::ReplayExchangeStatus::AwaitingClientTermination;
            return Err(HttpReplayMatchError::ClientTerminated(Box::new(
                termination::PendingHttpTermination::new(detail, &exchange.record),
            )));
        }
        if recorded_upstream_failure {
            upstream_failure::materialize(&mut exchange.record);
        }
        if exchange.record.response_stream.is_some() {
            self.http_exchanges[index].status = if exchange.record.outcome.is_client_terminated() {
                crate::replay::ReplayExchangeStatus::AwaitingClientTermination
            } else {
                crate::replay::ReplayExchangeStatus::Responding
            };
            self.refresh_http_global_report(index);
            exchange.record.stream_delivery = Some(detail);
            return Ok(exchange.record);
        }
        self.http_exchanges[index].status = crate::replay::ReplayExchangeStatus::Consumed;
        self.refresh_http_global_report(index);
        self.complete_http_exchange(detail);
        Ok(exchange.record)
    }
}
