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

        let mut matching_index = None;
        let mut matching_policy_decision = DependencyRuleDecision::default();
        let mut matching_dynamic_decision =
            crate::replay::policy::dynamic_values::DynamicDecision::default();
        let mut matching_request_decision = None;
        let mut closest_mismatch = None;
        let mut target_fingerprint = None;
        'sources: for source in [ReplaySource::Case, ReplaySource::Global] {
            for (index, exchange) in self.http_exchanges.iter().enumerate() {
                if !exchange.status.is_available() && !exchange.is_repeatable_preflight_probe()
                    || exchange.source != source
                    || !active_http_case_matches(active_case_id.as_deref(), exchange)
                    || exchange.identity.scheme != scheme
                    || exchange.identity.target != *target
                {
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
                let normalized =
                    if exchange.source == ReplaySource::Case && exchange.shared_origin.is_none() {
                        self.replay_policy.as_ref().and_then(|policy| {
                            if !policy.dynamic_values.enabled() {
                                return None;
                            }
                            decode_body(&exchange.record.request_body).ok().and_then(
                                |source_body| {
                                    policy.dynamic_values.http(
                                        exchange.case_id.as_deref(),
                                        target,
                                        method.as_str(),
                                        crate::replay::policy::dynamic_values::HttpInput {
                                            uri: &exchange.record.uri,
                                            body: &source_body,
                                        },
                                        crate::replay::policy::dynamic_values::HttpInput {
                                            uri: &uri.to_string(),
                                            body,
                                        },
                                    )
                                },
                            )
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
                let mut mismatch = http_request_mismatch_reason(
                    exchange,
                    method,
                    uri,
                    body,
                    &ignored_query_params,
                );
                if mismatch.as_deref() == Some("HTTP request body did not match the recorded body")
                    && exchange.shared_origin.is_none()
                    && let Some(policy) = &self.replay_policy
                    && let Ok(recorded_body) = decode_body(&exchange.record.request_body)
                    && policy.preview_http_json(
                        &HttpPolicyContext {
                            case_id: active_case_id.as_deref(),
                            target,
                            method: method.as_str(),
                            recorded_uri: &exchange.record.uri,
                            actual_uri: &uri.to_string(),
                        },
                        &recorded_body,
                        body,
                        &mut policy_decision,
                    )
                {
                    mismatch = None;
                }
                let mut request_decision = None;
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
                            );
                        }
                    }
                }
                if let Some(reason) = mismatch {
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
                matching_request_decision = request_decision;
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
            return Err(HttpReplayMatchError::BadGateway(reason));
        };
        let exchange = self.http_exchanges[index].clone();
        if !exchange.record.outcome.is_client_terminated()
            && (exchange.record.error.is_some() || exchange.record.response_status.is_none())
        {
            self.http_exchanges[index].status = crate::replay::ReplayExchangeStatus::Consumed;
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
                request_fingerprint: None,
                unordered_json: None,
            });
            return Err(HttpReplayMatchError::BadGateway(reason));
        }

        let mut audited_headers = headers.clone();
        if matching_request_decision.is_some() {
            audited_headers.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
            for (name, values) in &exchange.record.request_headers {
                if name.eq_ignore_ascii_case("content-type") {
                    audited_headers.insert(name.clone(), values.clone());
                }
            }
        }
        self.audit_http_request_headers(&exchange, index, &audited_headers, request_started_at);
        if let Some(policy) = &mut self.replay_policy {
            if let Some(case) = active_case_id.as_deref() {
                policy
                    .dynamic_values
                    .commit(case, matching_dynamic_decision);
            }
            policy.commit(active_case_id.as_deref(), matching_policy_decision);
            if let Some(decision) = matching_request_decision {
                policy.request_contracts.commit(decision);
            }
        }
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
        if exchange.record.outcome.is_client_terminated() {
            self.http_exchanges[index].status =
                crate::replay::ReplayExchangeStatus::AwaitingClientTermination;
            return Err(HttpReplayMatchError::ClientTerminated(Box::new(
                termination::PendingHttpTermination::new(detail, &exchange.record),
            )));
        }
        self.http_exchanges[index].status = crate::replay::ReplayExchangeStatus::Consumed;
        self.complete_http_exchange(detail);
        Ok(exchange.record)
    }
}
