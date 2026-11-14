//! Real Target GETs read the current matched value; only timestamp refreshes repeat.
use super::*;
use crate::replay::report::command::CommandMatchDiagnostic;

impl RedisReplayState {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay::redis) fn match_activity(
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
        if !matches!(command, "GET" | "SET") || args.is_empty() {
            return Ok(None);
        }
        let selected = self
            .activity_refresh
            .profiles
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                p.case == case
                    && p.database == database
                    && p.resp_version == resp_version
                    && normalize_optional(p.username.as_deref()) == normalize_optional(username)
                    && target_matches(target, &p.target.host, p.target.port)
                    && p.current
                        .as_ref()
                        .is_some_and(|c| c.key == args[0] && p.lifetimes[c.lifetime].eligible())
            })
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let Some(&profile) = selected.first() else {
            return Ok(None);
        };
        if selected.len() != 1 {
            return Err(self.activity_mismatch(profile, "activity key ownership is ambiguous"));
        }
        self.prepare_activity_match(profile, target, connection, command, args)
            .map(Some)
            .map_err(|error| self.activity_mismatch(profile, &format!("{error:#}")))
    }

    fn prepare_activity_match(
        &mut self,
        profile: usize,
        target: &TargetKey,
        connection: TargetConnection,
        command: &str,
        args: &[Vec<u8>],
    ) -> Result<MatchedRedisExchange> {
        let p = &self.activity_refresh.profiles[profile];
        let current = p
            .current
            .as_ref()
            .context("activity lifetime is not established")?;
        let lifetime = current.lifetime;
        let l = &p.lifetimes[lifetime];
        ensure!(
            !p.failed,
            "an activity delivery failed; its state is no longer proven"
        );
        ensure!(
            matches!(
                self.exchanges[l.creation].status,
                ReplayExchangeStatus::Responding | ReplayExchangeStatus::Consumed
            ),
            "activity creation has not been claimed"
        );
        ensure!(
            current.established_at.elapsed() < std::time::Duration::from_secs(l.ttl_seconds),
            "activity lifetime reaches its proven positive TTL"
        );
        ensure!(
            self.activity_refresh
                .calls
                .get(&p.case)
                .copied()
                .unwrap_or(0)
                < MAX_CALLS,
            "activity Target call bound exceeded"
        );
        let (witness, response, kind, next) = if command == "GET" {
            ensure!(args.len() == 1, "activity GET must have exactly one key");
            (
                *l.reads
                    .first()
                    .context("activity lifetime has no Source GET")?,
                value::bulk(&current.bytes),
                Completion::Read,
                None,
            )
        } else {
            ensure!(
                args.len() == 4 && args[2..] == l.ttl_args,
                "activity SET changed TTL, options or argument count"
            );
            ensure!(current.reads > 0, READ_REQUIRED);
            let witness = *l
                .writes
                .first()
                .context("activity lifetime has no Source refresh SET")?;
            let next = value::decode(&args[1])?;
            let e = &self.exchanges[witness];
            let source_clock = e
                .record
                .started_at()
                .context("activity Source refresh clock missing")?;
            let actual_clock = self
                .request_observed_at
                .context("activity Target request clock missing")?;
            // The Target's established stable object, not a Source or future value,
            // owns every leaf outside the explicitly selected timestamp fields.
            ensure!(
                value::stable(&current.value, &l.fields)? == value::stable(&next, &l.fields)?,
                "activity SET changed an unselected field, type or field set"
            );
            let mut reference = current.value.clone();
            // Reference clocks belong to the first successful refresh, not creation.
            let source_value = value::decode(&e.args[1])?;
            for (pointer, _) in &l.fields {
                *reference
                    .pointer_mut(pointer)
                    .context("activity timestamp missing")? = source_value
                    .pointer(pointer)
                    .context("activity Source timestamp missing")?
                    .clone();
            }
            value::check(&reference, &next, &l.fields, source_clock, actual_clock)?;
            (
                witness,
                b"+OK\r\n".to_vec(),
                Completion::Refresh,
                Some(next),
            )
        };
        ensure!(
            self.connection_scopes
                .matches(&self.exchanges[witness], Some(&p.case), connection),
            "activity request uses an incompatible connection scope"
        );
        let prepared = self.activity_prepared(profile, lifetime, witness, command, args, kind);
        let current = self.activity_refresh.profiles[profile]
            .current
            .as_mut()
            .unwrap();
        if let Some(next) = next {
            current.reads -= 1;
            current.value = next;
            current.bytes = args[1].clone();
        }
        let e = &self.exchanges[witness];
        let timing = if self.activity_refresh.charged.insert(witness) {
            e.timing
        } else {
            ReplayExchangeTiming::from_recorded(0, DependencyExchangeOutcome::Response)
        };
        Ok(MatchedRedisExchange {
            claim: Claim::Native(NativeClaimKind::ActivityRefresh),
            refresh: Some(prepared),
            observation: None,
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
            response,
            timing,
            requires_binding: false,
            rule_ids: vec![self.activity_refresh.profiles[profile].rule.clone()],
            report: CommandMatchedReport {
                case_id: Some(self.activity_refresh.profiles[profile].case.clone()),
                source: e.source,
                index: witness,
                target: target.clone(),
                connection_id: e.record.native.connection_id,
                sequence: e.record.native.sequence,
                command: command.into(),
                shared_origin: None,
                target_event_index: self.request_event_index,
            },
        })
    }

    pub(super) fn activity_prepared(
        &mut self,
        profile: usize,
        lifetime: usize,
        witness: usize,
        command: &str,
        args: &[Vec<u8>],
        kind: Completion,
    ) -> Prepared {
        let case = &self.activity_refresh.profiles[profile].case;
        let prepared = Prepared {
            profile,
            lifetime,
            witness,
            kind,
            token: Uuid::new_v4(),
            command: command.into(),
            observation: self.request_observation_id,
            event_index: self.request_event_index,
            target_key_fingerprint: fingerprint(&args[0]),
            target_value_fingerprint: fingerprint(
                args.get(1)
                    .map(Vec::as_slice)
                    .or_else(|| {
                        self.activity_refresh.profiles[profile]
                            .current
                            .as_ref()
                            .map(|c| c.bytes.as_slice())
                    })
                    .unwrap_or_default(),
            ),
        };
        *self.activity_refresh.calls.entry(case.clone()).or_default() += 1;
        self.activity_refresh.pending.insert(
            prepared.token,
            Pending {
                profile,
                lifetime,
                kind,
                event_index: prepared.event_index,
            },
        );
        prepared
    }

    fn activity_mismatch(&self, profile: usize, reason: &str) -> CommandMatchDiagnostic {
        let p = &self.activity_refresh.profiles[profile];
        let creation = p.current.as_ref().map(|c| p.lifetimes[c.lifetime].creation);
        CommandMatchDiagnostic::RedisStateObservationMismatch {
            rule_id: p.rule.clone(),
            source_key_fingerprint: fingerprint(&p.key),
            source_epoch_mutation: creation
                .map(|index| Box::new(reference(&self.exchanges[index]))),
            reason: reason.into(),
        }
    }
}

pub(super) fn reference(
    e: &ReplayExchange,
) -> super::super::super::report::command::CommandExchangeRefReport {
    super::super::super::report::command::CommandExchangeRefReport {
        case_id: e.case_id.clone(),
        source: e.source,
        connection_id: e.record.native.connection_id,
        sequence: e.record.native.sequence,
        command: e.record.native.command.clone(),
    }
}
