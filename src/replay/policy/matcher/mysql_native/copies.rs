//! Copy permission is a preview of real, case-local read delivery provenance.
use super::*;
use crate::mysql::sql::field_bindings::FieldIdentity;
use crate::replay::policy::request_contract::RequestContracts;
use crate::value_contract::{
    json::VerifiedTimeCopy,
    time_copies::{self, TimeCopyLookup, TimeCopyPosition, TimeCopyStore},
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
    pub(super) fn prepare(
        &self,
        rule: &CompiledRule,
        value: &Value,
        source: &FieldIdentity,
        target: &FieldIdentity,
        root: &str,
    ) -> Result<Vec<TimeCopyLookup>> {
        if !self.available {
            return Ok(vec![]);
        }
        let (Some(source_database), Some(target_database), Some(resource)) = (
            source.database.as_deref(),
            target.database.as_deref(),
            rule.rule.selector.resource.as_ref(),
        ) else {
            return Ok(vec![]);
        };
        let source_position = TimeCopyPosition::Mysql {
            host: &resource.endpoint.host,
            port: resource.endpoint.port,
            database: source_database,
            table: &source.table,
            column: &source.column,
        };
        let target_position = TimeCopyPosition::Mysql {
            host: &resource.endpoint.host,
            port: resource.endpoint.port,
            database: target_database,
            table: &target.table,
            column: &target.column,
        };
        Ok(time_copies::leaves(value, rule)?
            .into_iter()
            .filter_map(|leaf| {
                TimeCopyLookup::new_time(
                    &leaf.time,
                    source_position,
                    target_position,
                    &leaf.pattern,
                    &leaf.pattern,
                    &leaf.value,
                    &rule.rule.id,
                )
                .map(|lookup| {
                    lookup.at(
                        &format!("{root}{}", leaf.pointer),
                        &format!("{root}{}", leaf.pattern),
                    )
                })
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
