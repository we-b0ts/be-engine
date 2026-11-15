//! A real primary cancellation permits differences in an expiring stream cache's tail.
//! Source inventory and wire delivery stay intact; this is a separate allowance.
use super::*;
mod source;
pub(crate) use source::load;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(super) struct Cache {
    closed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Audit {
    rule_id: String,
    case_id: String,
    reason: &'static str,
    source_key_fingerprint: String,
    source_bytes: usize,
    target_bytes: usize,
    response_prefix_bytes: usize,
    omitted_source_bytes: usize,
    additional_target_bytes: usize,
    partially_or_fully_omitted_source_exchanges: usize,
}

impl RedisReplayState {
    pub(crate) fn permits_cancelled_append_omission(&self, index: usize) -> bool {
        self.append_streams.allows_cancelled_omission(index)
    }
    pub(crate) fn prepare_cancelled_caches(
        &mut self,
        case: &str,
        candidates: Vec<Vec<u8>>,
    ) -> Result<()> {
        if candidates.is_empty() {
            return Ok(());
        }
        self.prepare_append_case(case)?;
        let mut total = self
            .append_streams
            .profiles
            .iter()
            .map(|p| p.bytes.len())
            .sum::<usize>();
        for profile in self
            .append_streams
            .profiles
            .iter_mut()
            .filter(|p| p.case == case)
        {
            // A read/reset fence or a preexisting value can represent durable
            // state. Only write-only, initially empty, expiring caches qualify.
            if !profile.barriers.is_empty() || profile.pieces[0].base != 0 {
                continue;
            }
            let expiring = self.exchanges.iter().any(|e| {
                e.source == ReplaySource::Case
                    && e.case_id.as_deref() == Some(case)
                    && e.record.native.database == profile.database
                    && target_matches(
                        &profile.target,
                        &e.record.native.target_host,
                        e.record.native.target_port,
                    )
                    && normalize_optional(e.record.native.username.as_deref())
                        == normalize_optional(profile.username.as_deref())
                    && matches!(e.record.native.command.as_str(), "EXPIRE" | "PEXPIRE")
                    && e.args.first() == Some(&profile.key)
            });
            if !expiring {
                continue;
            }
            let mut matching = candidates
                .iter()
                .filter(|bytes| bytes.starts_with(&profile.bytes));
            let Some(bytes) = matching.next() else {
                continue;
            };
            if matching.any(|other| other != bytes) {
                continue;
            }
            let extra = bytes.len() - profile.bytes.len();
            if extra > MAX_BYTES.saturating_sub(total) {
                continue;
            }
            total += extra;
            profile.bytes = bytes.clone();
            profile.cancelled_cache = Some(Cache { closed: false });
            tracing::debug!(
                case_id = case,
                source_bytes = profile.pieces.last().unwrap().end,
                response_prefix_bytes = profile.bytes.len(),
                "prepared cancelled stream cache prefix"
            );
        }
        Ok(())
    }

    pub(crate) fn confirm_cancelled_caches(&mut self, case: &str) {
        for profile in self
            .append_streams
            .profiles
            .iter_mut()
            .filter(|p| p.case == case)
        {
            if let Some(cache) = &mut profile.cancelled_cache {
                cache.closed = true;
            }
        }
    }

    pub(in crate::protocols::replay::redis) fn cancelled_cache_audits(&self) -> Vec<Audit> {
        self.append_streams
            .profiles
            .iter()
            .filter(|p| allowed(p))
            .map(|p| {
                let source_bytes = p.pieces.last().unwrap().end;
                Audit {
                    rule_id: p.rule.clone(),
                    case_id: p.case.clone(),
                    reason: "client_cancelled_expiring_stream_cache_prefix",
                    source_key_fingerprint: crate::policy_evidence::digest(&p.key),
                    source_bytes,
                    target_bytes: p.delivered,
                    response_prefix_bytes: p.bytes.len(),
                    omitted_source_bytes: source_bytes.saturating_sub(p.delivered),
                    additional_target_bytes: p.delivered.saturating_sub(source_bytes),
                    partially_or_fully_omitted_source_exchanges: p
                        .pieces
                        .iter()
                        .filter(|piece| piece.end > p.delivered)
                        .count(),
                }
            })
            .collect()
    }
}

fn allowed(profile: &Profile) -> bool {
    profile.cancelled_cache.as_ref().is_some_and(|c| c.closed)
        && !profile.failed
        && profile.in_flight.is_empty()
        && profile.delivered == profile.reserved
}

impl AppendStreams {
    pub(in crate::protocols::replay::redis) fn allows_cancelled_omission(
        &self,
        index: usize,
    ) -> bool {
        self.owners
            .get(&index)
            .is_some_and(|(owner, _)| allowed(&self.profiles[*owner]))
    }
    pub(in crate::protocols::replay::redis) fn unconfirmed_extension(&self, case: &str) -> bool {
        self.profiles
            .iter()
            .any(|p| p.case == case && p.reserved > p.pieces.last().unwrap().end && !allowed(p))
    }
    pub(in crate::protocols::replay::redis) fn has_in_flight(&self) -> bool {
        self.profiles.iter().any(|p| !p.in_flight.is_empty())
    }
    pub(in crate::protocols::replay::redis) fn unconfirmed_extensions(
        &self,
    ) -> Vec<CommandRequestReport> {
        self.profiles.iter().filter(|p| p.reserved > p.pieces.last().unwrap().end && !allowed(p)).map(|p| CommandRequestReport {
            target_observation_id: None, case_id: Some(p.case.clone()), target: p.target.clone(),
            command: "APPEND".into(), target_event_index: None, request_fingerprint: None,
            reason: "stream cache extension requires actual primary client cancellation and successful wire delivery".into(), diagnostic: None,
        }).collect()
    }
}
