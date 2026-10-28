//! Copy permission is a preview of real, case-local read delivery provenance.
use super::*;
use crate::mysql::sql::field_bindings::FieldIdentity;
use crate::replay::policy::request_contract::RequestContracts;
use crate::value_contract::{
    json::VerifiedTimeCopy,
    time_copies::{TimeCopyLookup, TimeCopyPosition, TimeCopyStore},
};

enum Source<'a> {
    Runtime(&'a RequestContracts),
    Stored(&'a TimeCopyStore),
}

pub(crate) struct CopyProofs<'a> {
    case: &'a str,
    source: Source<'a>,
    available: bool,
    clocks: crate::value_contract::time::ClockPair,
}

impl<'a> CopyProofs<'a> {
    pub(in crate::replay) fn runtime(
        owner: &'a RequestContracts,
        case: &'a str,
        clocks: crate::value_contract::time::ClockPair,
    ) -> Self {
        Self {
            case,
            source: Source::Runtime(owner),
            available: owner.has_time_copies(case),
            clocks,
        }
    }
    pub(crate) fn stored(store: &'a TimeCopyStore, case: &'a str) -> Self {
        Self {
            case,
            source: Source::Stored(store),
            available: store.has_case(case),
            clocks: Default::default(),
        }
    }
    /// Global JSON describes content independently of its carrier. An exact
    /// typed pair already delivered in this case keeps that provenance when
    /// copied into SQL, provided both deliveries precede this request.
    pub(super) fn resolve_global(
        &self,
        context: &crate::replay::mysql::contracts::automatic::RequestContext<'_>,
        selected: &crate::replay::mysql::contracts::automatic::Selection,
        origin: Option<&FieldIdentity>,
        clocks: AnchorClocks,
    ) -> Result<Vec<VerifiedTimeCopy>> {
        let mut verified = if let Some(origin) = origin {
            self.resolve(self.prepare_global(context, selected, origin, clocks)?)
        } else {
            vec![]
        };
        if !self.available || selected.id != crate::policy::GLOBAL_JSON_ID {
            return Ok(verified);
        }
        if let Some(plan) = &context.policy.global_json {
            let (delivered, observed) = match self.source {
                Source::Runtime(owner) => (owner.delivered_time_copies(self.case), self.clocks),
                Source::Stored(store) => (store.delivered_copies(self.case), clocks.dependency),
            };
            verified.extend(delivered.proofs(&selected.source, plan, clocks, observed)?);
        }
        Ok(verified)
    }

    pub(super) fn prepare_global(
        &self,
        context: &crate::replay::mysql::contracts::automatic::RequestContext<'_>,
        selected: &crate::replay::mysql::contracts::automatic::Selection,
        origin: &FieldIdentity,
        clocks: AnchorClocks,
    ) -> Result<Vec<TimeCopyLookup>> {
        if !self.available {
            return Ok(vec![]);
        }
        let (Some(endpoint), Some(database)) =
            (context.identity.target.as_ref(), origin.database.as_deref())
        else {
            return Ok(vec![]);
        };
        let position = TimeCopyPosition::Mysql {
            host: &endpoint.host,
            port: endpoint.port,
            database,
            table: &origin.table,
            column: &origin.column,
        };
        Ok(crate::replay::mysql::contracts::automatic::time_leaves(
            selected,
            context.policy,
            clocks,
        )?
        .into_iter()
        .filter_map(|leaf| {
            TimeCopyLookup::new_time(
                &leaf.time,
                position,
                position,
                &leaf.pattern,
                &leaf.pattern,
                &leaf.value,
                selected.id,
            )
            .map(|lookup| lookup.at(&leaf.pointer, &leaf.pattern))
        })
        .collect())
    }

    /// Every selected physical field contributes prepared hashes before this
    /// one short lookup lock for the complete SQL candidate.
    pub(super) fn resolve(&self, lookups: Vec<TimeCopyLookup>) -> Vec<VerifiedTimeCopy> {
        match self.source {
            Source::Runtime(owner) => owner.time_copy_proofs(self.case, lookups, self.clocks),
            Source::Stored(store) => lookups
                .iter()
                .filter_map(|lookup| store.proof_prepared(self.case, lookup))
                .collect(),
        }
    }
}
