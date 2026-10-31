//! A successful terminal SQL write inside a transaction is not committed work.
use super::AsyncSignal;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Default)]
pub(super) struct Transactions(BTreeMap<Uuid, Pending>);

#[derive(Debug)]
struct Pending {
    sequence: u64,
    status: u16,
    signal: AsyncSignal,
}

pub(super) struct Facts<'a> {
    pub connection_id: Uuid,
    pub sequence: u64,
    pub before: Option<u16>,
    pub after: Option<u16>,
    pub sql: Option<&'a str>,
    pub successful: bool,
}

impl Transactions {
    pub(super) fn observe(
        &mut self,
        facts: Facts<'_>,
        signal: Option<AsyncSignal>,
    ) -> Option<AsyncSignal> {
        let previous = self.0.remove(&facts.connection_id);
        if !facts.successful {
            return None;
        }
        let after = facts.after?;
        let tokens = facts.sql.and_then(crate::mysql::sql::tokens);
        let commit = tokens.as_ref().is_some_and(|tokens| {
            tokens.first().is_some_and(|t| t.is("commit"))
                && (tokens.len() == 1 || tokens.len() == 2 && tokens[1].is("work"))
        });
        let restart = tokens.as_ref().is_some_and(|tokens| {
            tokens
                .first()
                .is_some_and(|t| t.is("rollback") || t.is("begin") || t.is("start"))
        });
        let contiguous = previous.filter(|p| {
            p.sequence.checked_add(1) == Some(facts.sequence)
                && facts
                    .before
                    .is_some_and(|before| before & 0x200b == p.status & 0x200b)
                && after & 0x2008 == 0
                && !restart
        });
        if let Some(signal) = signal {
            if after & 1 == 0 {
                return Some(signal);
            }
            if self.0.len() < 4096 {
                self.0.insert(
                    facts.connection_id,
                    Pending {
                        sequence: facts.sequence,
                        status: after,
                        signal,
                    },
                );
            }
        } else if let Some(mut pending) = contiguous {
            if commit && after & 1 == 0 {
                return Some(pending.signal);
            }
            if after & 1 != 0 {
                pending.sequence = facts.sequence;
                pending.status = after;
                self.0.insert(facts.connection_id, pending);
            }
        }
        None
    }
}
