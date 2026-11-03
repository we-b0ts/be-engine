//! A successful terminal SQL write inside a transaction is not committed work.
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Default)]
pub(super) struct Transactions(BTreeMap<Uuid, Pending>);

#[derive(Debug)]
struct Pending {
    sequence: u64,
    status: u16,
    resources: u32,
}

pub(super) struct Facts<'a> {
    pub connection_id: Uuid,
    pub sequence: u64,
    pub before: Option<u16>,
    pub after: Option<u16>,
    pub tokens: Option<&'a [crate::mysql::sql::Token]>,
    pub successful: bool,
}

impl Transactions {
    pub(super) fn needs_tokens(&self, connection: Uuid, resources: u32) -> bool {
        resources != 0 || self.0.contains_key(&connection)
    }

    pub(super) fn observe(&mut self, facts: Facts<'_>, mut resources: u32) -> u32 {
        let previous = self.0.remove(&facts.connection_id);
        if !facts.successful {
            return 0;
        }
        let Some(after) = facts.after else {
            return 0;
        };
        // Unknown or compound SQL cannot prove uninterrupted transaction state.
        let Some(tokens) = facts.tokens else {
            return 0;
        };
        let commit = tokens.first().is_some_and(|t| t.is("commit"))
            && (tokens.len() == 1 || tokens.len() == 2 && tokens[1].is("work"));
        let restart = tokens
            .first()
            .is_some_and(|t| t.is("rollback") || t.is("begin") || t.is("start"));
        let contiguous = previous.filter(|p| {
            p.sequence.checked_add(1) == Some(facts.sequence)
                && facts
                    .before
                    .is_some_and(|before| before & 0x200b == p.status & 0x200b)
                && after & 0x2008 == 0
                && !restart
        });
        if after & 1 == 0 {
            if commit && let Some(pending) = contiguous {
                resources |= pending.resources;
            }
            return resources;
        }
        if let Some(pending) = contiguous {
            resources |= pending.resources;
        }
        if resources != 0 && self.0.len() < 4096 {
            self.0.insert(
                facts.connection_id,
                Pending {
                    sequence: facts.sequence,
                    status: after,
                    resources,
                },
            );
        }
        0
    }
}
