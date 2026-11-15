//! Native Memcached candidate guards and finite Source claims.
use super::*;

pub(super) fn observe_request(context: MemcachedMatchContext<'_>) -> Option<Uuid> {
    let request_id = uuid::Uuid::new_v4();
    let mut observation_id = Some(request_id);
    if let (Some(policy), Some(case)) = (context.policy, context.active_case_id) {
        match contracts::record_target(
            policy,
            case,
            context.target,
            context.wire_protocol.as_str(),
            context.request,
            (request_id, context.observed_at),
        ) {
            Ok(crate::policy_evidence::ObservationRetention::Unavailable) => observation_id = None,
            Ok(crate::policy_evidence::ObservationRetention::Retained) => {}
            Err(error) => {
                tracing::warn!(%error, "failed to preserve independent Memcached Target observation")
            }
        }
    }
    observation_id
}

impl MemcachedReplayState {
    #[cfg(test)]
    pub(super) fn match_memcached(
        &mut self,
        context: MemcachedMatchContext<'_>,
    ) -> std::result::Result<MatchedMemcachedExchange, CommandMatchDiagnostic> {
        let observation = observe_request(context);
        let event = self.events.request_order.reserve(context.active_case_id);
        let mut matched = self.select_memcached(context, observation)?;
        matched.report.target_event_index = Some(event);
        Ok(matched)
    }

    pub(super) fn select_memcached(
        &mut self,
        context: MemcachedMatchContext<'_>,
        observation_id: Option<Uuid>,
    ) -> std::result::Result<MatchedMemcachedExchange, CommandMatchDiagnostic> {
        let MemcachedMatchContext {
            active_case_id,
            target,
            wire_protocol,
            request,
            policy,
            observed_at,
        } = context;
        let wire = wire_protocol.as_str();
        let matched = preferred_match(&self.exchanges, active_case_id, |exchange| {
            exchange.status.is_available()
                && target_matches(
                    target,
                    &exchange.record.target_host,
                    exchange.record.target_port,
                )
                && exchange.record.wire_protocol == wire
                && exchange
                    .record
                    .command
                    .eq_ignore_ascii_case(&request.command)
                && binary_get_opcodes_match(exchange.record.opcode, request.opcode)
                && exchange.key == request.key
                && policy.is_none_or(|policy| {
                    if let Err(error) = contracts::record_request(
                        policy,
                        exchange,
                        request,
                        observed_at,
                        observation_id,
                    ) {
                        tracing::warn!(%error, "failed to preserve Memcached request witness");
                        return false;
                    }
                    true
                })
                && contracts::request_arguments_match(
                    policy,
                    exchange,
                    target,
                    wire_protocol,
                    request,
                    observed_at,
                )
                && memcached_value_matches_policy(policy, exchange, target, request, observed_at)
                && exchange.record.cas == request.cas
                && (exchange.record.quiet == request.quiet
                    || binary_get_opcodes_match(exchange.record.opcode, request.opcode))
                && exchange.record.noreply == request.noreply
        });
        let index = match matched {
            PreferredMatch::Matched(index) => index,
            PreferredMatch::LaneBlocked { candidate, blocker } => {
                return Err(lane_blocked_diagnostic(&self.exchanges, candidate, blocker));
            }
            PreferredMatch::NotFound => {
                return Err(unmatched_diagnostic(
                    &self.exchanges,
                    active_case_id,
                    |exchange| {
                        memcached_mismatch_fields(
                            exchange,
                            target,
                            wire_protocol,
                            request,
                            observed_at,
                        )
                    },
                ));
            }
        };
        let response_frames = self.exchanges[index].response_bytes().map_err(|error| {
            CommandMatchDiagnostic::EvidenceUnavailable {
                reason: format!("response evidence unavailable: {error:#}"),
            }
        })?;
        let exchange = &mut self.exchanges[index];
        let policy_decision = policy
            .map(|policy| {
                policy
                    .preview_memcached(&memcached_policy_context(
                        exchange,
                        target,
                        request,
                        observed_at,
                    ))
                    .expect("matched Memcached policy preview must remain stable")
            })
            .unwrap_or_default();
        let kind = if exchange.timing.outcome().is_client_terminated() {
            ClaimKind::ClientTermination
        } else {
            ClaimKind::Response
        };
        let claim = self
            .lifecycle
            .claim(index, &mut exchange.status, kind)
            .ok_or_else(|| CommandMatchDiagnostic::EvidenceUnavailable {
                reason: "recorded Memcached exchange could not be claimed".into(),
            })?;
        exchange.claim = Some(claim.observer());
        Ok(MatchedMemcachedExchange {
            response_frame_offsets_ms: exchange.record.response_frame_offsets_ms.clone(),
            index,
            claim,
            response_frames,
            timing: exchange.timing,
            request_observed_at: observed_at,
            request_opcode: request.opcode,
            request_opaque: request.opaque,
            policy_decision,
            report: CommandMatchedReport {
                case_id: active_case_id.map(ToOwned::to_owned),
                source: exchange.source,
                index,
                target: target.clone(),
                connection_id: exchange.record.connection_id,
                sequence: exchange.record.sequence,
                command: exchange.record.command.clone(),
                shared_origin: None,
                target_event_index: None,
            },
        })
    }
}
