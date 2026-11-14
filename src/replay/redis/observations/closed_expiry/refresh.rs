//! Extra refreshes derive their response from a delivered initial TTL, never a
//! manufactured Source EXPIRE. Finite creation, reads and closure stay required.
use super::*;
#[cfg(test)]
mod tests;

impl RedisReplayState {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay::redis) fn match_initial_expiry(
        &mut self,
        case: &str,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
    ) -> std::result::Result<Option<MatchedRedisExchange>, CommandMatchDiagnostic> {
        if command != "EXPIRE" || args.is_empty() {
            return Ok(None);
        }
        let key = fingerprint(&args[0]);
        let mut selected = None;
        for (owner, p) in self.observations.profiles.iter().enumerate() {
            if p.kind != Kind::Expiry
                || p.case != case
                || p.database != database
                || p.resp_version != resp_version
                || normalize_optional(p.username.as_deref()) != normalize_optional(username)
                || !target_matches(target, &p.target.host, p.target.port)
            {
                continue;
            }
            let active = p.epochs.iter().rev().find_map(|epoch| {
                epoch
                    .mutation
                    .filter(|&i| self.exchanges[i].satisfies_lane_order())
            });
            for (lifetime, l) in p.closed_expiry.iter().enumerate() {
                if !p.epochs[l.epoch].observations.is_empty()
                    || active != Some(l.creation)
                    || l.creation_key.as_deref() != Some(&key)
                {
                    continue;
                }
                let reject = |reason| self.observation_mismatch(p, &p.epochs[l.epoch], reason);
                if selected.is_some() {
                    return Err(reject("initial-TTL refresh ownership is ambiguous"));
                }
                if args.len() != 2 || args[1] != l.ttl.as_secs().to_string().as_bytes() {
                    return Err(reject(
                        "refresh TTL or options differ from the initial Source SET",
                    ));
                }
                if p.failed
                    || l.failed
                    || p.epochs
                        .iter()
                        .filter_map(|e| e.mutation)
                        .any(|i| self.exchanges[i].status == ReplayExchangeStatus::Failed)
                {
                    return Err(reject(
                        "an earlier key delivery failed; initial TTL is not proven",
                    ));
                }
                if !self.exchanges[l.creation].status.is_consumed()
                    || !self.connection_scopes.matches(
                        &self.exchanges[l.creation],
                        Some(case),
                        connection,
                    )
                {
                    return Err(reject(
                        "initial TTL creation has not completed on an eligible connection",
                    ));
                }
                if l.established.is_none_or(|start| start.elapsed() >= l.ttl) {
                    return Err(reject("initial TTL deadline has been reached"));
                }
                if self.observations.calls.get(case).copied().unwrap_or(0) >= MAX_CALLS {
                    return Err(reject("Target state-observation call limit exceeded"));
                }
                selected = Some((owner, lifetime));
            }
        }
        let Some((owner, lifetime)) = selected else {
            return Ok(None);
        };
        let p = &self.observations.profiles[owner];
        let l = &p.closed_expiry[lifetime];
        let witness = l.creation;
        let prepared = Prepared {
            profile: owner,
            epoch: l.epoch,
            token: Uuid::new_v4(),
            target_event_index: self.request_event_index,
            target_key_fingerprint: key,
            initial_expiry: Some(lifetime),
        };
        self.observations.in_flight.insert(prepared.token, owner);
        *self.observations.calls.entry(case.into()).or_default() += 1;
        self.observations.profiles[owner].closed_expiry[lifetime].used_refresh = true;
        let p = &self.observations.profiles[owner];
        let e = &self.exchanges[witness];
        Ok(Some(MatchedRedisExchange {
            claim: Claim::Native(NativeClaimKind::StateObservation),
            observation: Some(prepared),
            refresh: None,
            append: None,
            read_back: None,
            time_read: None,
            time_write: None,
            unified_delivery: None,
            rpc_push: None,
            rpc_response: None,
            publish_duration_ms: 0,
            adapter_echo: None,
            index: witness,
            connection_id: e.record.native.connection_id,
            response: b":1\r\n".to_vec(),
            timing: ReplayExchangeTiming::from_recorded(0, DependencyExchangeOutcome::Response),
            requires_binding: false,
            rule_ids: vec![p.rule.clone()],
            report: CommandMatchedReport {
                case_id: Some(case.into()),
                source: ReplaySource::Case,
                index: witness,
                target: target.clone(),
                connection_id: e.record.native.connection_id,
                sequence: e.record.native.sequence,
                command: "EXPIRE".into(),
                shared_origin: None,
                target_event_index: None,
            },
        }))
    }

    pub(in crate::replay::redis) fn unsettled_initial_expiry(&self, case: &str) -> bool {
        self.observations
            .profiles
            .iter()
            .any(|p| p.case == case && p.closed_expiry.iter().any(|l| l.used_refresh && !l.settled))
    }

    pub(in crate::replay::redis) fn initial_expiry_violations(&self) -> Vec<CommandRequestReport> {
        self.observations.profiles.iter().flat_map(|p| {
            p.closed_expiry.iter().filter(|l| l.used_refresh && !l.settled).map(|l| {
                let reason = "initial-TTL refresh requires every finite read and deletion to finish delivery before the original TTL, with no failed or pending observation";
                CommandRequestReport {
                    target_observation_id: None,
                    case_id: Some(p.case.clone()), target: p.target.clone(),
                    command: "EXPIRE".into(), target_event_index: l.deletion_event,
                    request_fingerprint: None, reason: reason.into(),
                    diagnostic: Some(self.observation_mismatch(p, &p.epochs[l.epoch], reason)),
                }
            })
        }).collect()
    }
}

impl Lifetime {
    pub(in crate::replay::redis::observations) fn refresh_coverage(
        &self,
        state: &RedisReplayState,
    ) -> Coverage {
        Coverage::InitialExpiryRefresh {
            source_deletion: reference(&state.exchanges[self.deletion]),
            ttl_seconds: self.ttl.as_secs(),
            target_lifetime_ms: self
                .established
                .map_or(0, |start| start.elapsed().as_millis()),
        }
    }
}
