//! Finite lifecycle mutations and transport-complete refresh coverage.
use super::*;
use crate::replay::report::command::CommandMatchDiagnostic;

impl RedisReplayState {
    pub(in crate::replay::redis) fn check_activity_mutation(
        &self,
        index: usize,
    ) -> std::result::Result<(), CommandMatchDiagnostic> {
        for (profile, p) in self.activity_refresh.profiles.iter().enumerate() {
            for (lifetime, l) in p.lifetimes.iter().enumerate() {
                if l.creation != index && l.deletion != Some(index) {
                    continue;
                }
                let invalid = p.failed
                    || (l.creation == index
                        && (p.current.is_some()
                            || p.lifetimes[..lifetime].iter().any(|l| {
                                l.deletion
                                    .is_none_or(|i| !self.exchanges[i].status.is_consumed())
                            })))
                    || (l.deletion == Some(index)
                        && (p.current.as_ref().is_none_or(|c| c.lifetime != lifetime)
                            || self
                                .activity_refresh
                                .pending
                                .values()
                                .any(|pending| pending.profile == profile)));
                if invalid {
                    return Err(CommandMatchDiagnostic::RedisStateObservationMismatch {
                        rule_id: p.rule.clone(), source_key_fingerprint: fingerprint(&p.key),
                        source_epoch_mutation: Some(Box::new(super::runtime::reference(&self.exchanges[l.creation]))),
                        reason: "activity lifecycle mutation crosses an unestablished, failed or in-flight state".into(),
                    });
                }
            }
        }
        Ok(())
    }

    pub(in crate::replay::redis) fn reserve_activity_mutation(
        &mut self,
        index: usize,
        args: &[Vec<u8>],
    ) -> Result<Option<Prepared>> {
        let selected =
            self.activity_refresh
                .profiles
                .iter()
                .enumerate()
                .find_map(|(profile, p)| {
                    p.lifetimes.iter().enumerate().find_map(|(lifetime, l)| {
                        (l.creation == index || l.deletion == Some(index)).then_some((
                            profile,
                            lifetime,
                            l.creation == index,
                        ))
                    })
                });
        let Some((profile, lifetime, creation)) = selected else {
            return Ok(None);
        };
        let command = self.exchanges[index].record.command.clone();
        if creation {
            let next = value::decode(&args[1])?;
            self.activity_refresh.profiles[profile].current = Some(Current {
                lifetime,
                key: args[0].clone(),
                value: next,
                bytes: args[1].clone(),
                reads: 0,
                established_at: tokio::time::Instant::now(),
            });
        } else {
            self.activity_refresh.profiles[profile].current = None;
        }
        Ok(Some(self.activity_prepared(
            profile,
            lifetime,
            index,
            &command,
            args,
            if creation {
                Completion::Create
            } else {
                Completion::Delete
            },
        )))
    }

    pub(in crate::replay::redis) fn complete_activity(&mut self, prepared: &Prepared) {
        if self
            .activity_refresh
            .pending
            .remove(&prepared.token)
            .is_none()
        {
            return;
        }
        let p = &mut self.activity_refresh.profiles[prepared.profile];
        if matches!(prepared.kind, Completion::Read)
            && let Some(current) = &mut p.current
        {
            current.reads += 1;
        }
        let l = &p.lifetimes[prepared.lifetime];
        let indices = match prepared.kind {
            Completion::Read => l.reads.clone(),
            Completion::Refresh => l.writes.clone(),
            Completion::Create | Completion::Delete => vec![prepared.witness],
        };
        let covered = indices
            .iter()
            .filter(|&&i| !self.exchanges[i].status.is_consumed())
            .count();
        let audit = ActivityAudit {
            rule_id: p.rule.clone(),
            case_id: p.case.clone(),
            command: prepared.command.clone(),
            target_event_index: prepared.event_index,
            target_observation: prepared.observation,
            source_key_fingerprint: fingerprint(&p.key),
            target_key_fingerprint: prepared.target_key_fingerprint.clone(),
            target_value_fingerprint: prepared.target_value_fingerprint.clone(),
            source_creation: super::runtime::reference(&self.exchanges[l.creation]),
            source_witness: super::runtime::reference(&self.exchanges[prepared.witness]),
            covered_source_observations: covered,
        };
        for index in indices {
            self.exchanges[index].status = ReplayExchangeStatus::Consumed;
            self.exchanges[index].matched_once = true;
        }
        if self.activity_refresh.audits.len() < 1000 {
            self.activity_refresh.audits.push(audit);
        } else {
            self.activity_refresh.omitted += 1;
        }
    }

    pub(in crate::replay::redis) fn fail_activity(&mut self, prepared: &Prepared) {
        self.activity_refresh.pending.remove(&prepared.token);
        self.activity_refresh.profiles[prepared.profile].failed = true;
    }
}
