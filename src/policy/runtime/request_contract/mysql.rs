//! Source-scoped SQL value rules, complete witnesses and atomic accounting.
use super::*;
use crate::mysql::sql::{Token, bounds::statement_shared};
use crate::policy::{CompiledRule, Protocol, Slot, Surface};
use crate::policy_evidence::{
    ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata,
};
use crate::protocols::replay::mysql::RecordedMysqlExchange;
use crate::protocols::replay::mysql::{RecordedMysqlValue, ReplaySessionIdentity};
use crate::value_contract::json::AnchorClocks;
impl RequestContracts {
    pub(crate) fn prepare_mysql_candidate_witness(
        &self,
        case: &str,
        observation_id: uuid::Uuid,
        observed: DateTime<Utc>,
    ) -> Result<crate::protocols::replay::mysql::contracts::CandidateWitness> {
        use crate::value_contract::time::ClockPair;
        let anchor = self.anchor(case)?;
        let target = self
            .witnesses
            .as_ref()
            .context("MySQL candidate witness store is missing")?
            .prepare_request_association(&observation_id.to_string())?;
        Ok(
            crate::protocols::replay::mysql::contracts::CandidateWitness {
                target,
                key_context: anchor.dir,
                clocks: AnchorClocks::for_request(
                    ClockPair {
                        source: anchor.recorded,
                        target: anchor.actual,
                    },
                    ClockPair {
                        source: None,
                        target: Some(observed),
                    },
                    ClockPair::default(),
                ),
            },
        )
    }

    pub(crate) fn has_mysql_formats(
        &self,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
    ) -> bool {
        self.has_mysql_formats_in_scope(identity, record, false)
    }

    pub(crate) fn has_authored_mysql_formats(
        &self,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
    ) -> bool {
        self.has_mysql_formats_in_scope(identity, record, true)
    }

    fn has_mysql_formats_in_scope(
        &self,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        authored_only: bool,
    ) -> bool {
        let Some(policy) = self
            .compiled_rules()
            .filter(|policy| policy.global_json.is_some() || policy.mysql.is_some())
        else {
            return false;
        };
        if authored_only
            && policy.mysql.is_none()
            && policy
                .global_json
                .as_ref()
                .is_none_or(|plan| plan.fields.is_empty())
        {
            return false;
        }
        let Ok(tokens) = super::super::matcher::mysql_values::materialized(
            record.sql.as_deref(),
            record.params.as_deref(),
        ) else {
            return false;
        };
        let context = crate::protocols::replay::mysql::contracts::automatic::RequestContext::new(
            policy,
            self.mysql_automatic
                .lock()
                .expect("MySQL inference metadata")
                .clone(),
            identity,
            record,
        );
        let clocks = self.contract_clocks(
            None,
            crate::protocols::replay::mysql::contracts::source_started(record),
            None,
            None,
            None,
        );
        // A malformed declared field must still reach normal validation.
        if authored_only {
            context.selects_authored_values(&tokens, record.database.as_deref(), clocks)
        } else {
            context.selects_values(&tokens, record.database.as_deref(), clocks)
        }
        .unwrap_or(true)
    }
    /// PREPARE can prove SQL shape; runtime execution retains all value checks.
    pub(crate) fn mysql_fields_metadata_matches(
        &self,
        _case: Option<&str>,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        sql: &str,
    ) -> bool {
        if record.database != identity.database
            || !self
                .compiled_rules()
                .is_some_and(|policy| policy.global_json.is_some() || policy.mysql.is_some())
        {
            return false;
        }
        let Ok(source) = super::super::matcher::mysql_values::materialized(
            record.sql.as_deref(),
            record.params.as_deref(),
        ) else {
            return false;
        };
        let Some(actual) = crate::mysql::sql::bounds::statement_shared(sql) else {
            return false;
        };
        source.len() == actual.len()
            && source.iter().zip(actual.iter()).all(|(source, actual)| {
                source == actual
                    || (source.is_value()
                        && (actual.is_value() || *actual == crate::mysql::sql::Token::Placeholder))
            })
    }
    pub(crate) fn mysql_metadata(
        &self,
        case: &str,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        location: (Surface, Slot),
        role: TargetRole,
        clocks: AnchorClocks,
    ) -> WitnessMetadata {
        let (surface, slot) = location;
        let pair = |p: crate::value_contract::time::ClockPair| ClockPair {
            source: p.source,
            target: p.target,
        };
        WitnessMetadata {
            surface,
            source_role: if surface == Surface::DependencyRequest {
                SourceRole::DependencyRequest
            } else {
                SourceRole::DependencyResponse
            },
            target_role: role,
            source: SourceIdentity {
                case_id: case.into(),
                exchange_id: None,
                connection_id: record.connection_id.map(|id| id.to_string()),
                sequence: record.query_sequence,
            },
            resource: identity.target.as_ref().map(|t| crate::policy::Resource {
                protocol: Protocol::Mysql,
                endpoint: crate::policy::Endpoint {
                    host: t.host.clone(),
                    port: t.port,
                },
                database: identity.database.clone().map(crate::policy::Database::Name),
                username: identity.username.clone(),
            }),
            operation: record.command.clone(),
            slot,
            clocks: WitnessClocks {
                case: pair(clocks.case),
                dependency: pair(clocks.dependency),
                delivery: pair(clocks.delivery),
            },
        }
    }
    pub(super) fn observe_unified_mysql_source(&self, case: &str, event: &Value) -> Result<()> {
        if self.compiled.is_none() || event["event_type"] != "mysql_exchange" {
            return Ok(());
        }
        let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
        let Some(source_identity) =
            crate::protocols::replay::mysql::identity_from_exchange(&record)
        else {
            return Ok(());
        };
        let identity = ReplaySessionIdentity {
            target: Some(source_identity.target),
            database: source_identity.database,
            username: source_identity.username,
        };
        if self
            .compiled_rules()
            .is_some_and(|policy| policy.mysql.is_some() || policy.global_json.is_some())
        {
            self.mysql_automatic
                .lock()
                .expect("MySQL inference metadata")
                .observe(&identity, &record);
        }
        let clocks = self.contract_clocks(
            Some(case),
            crate::protocols::replay::mysql::contracts::source_started(&record),
            None,
            record.timestamp,
            None,
        );
        let automatic =
            crate::protocols::replay::mysql::contracts::automatic::validate_source_record(
                self, &identity, &record, clocks,
            )?;
        ensure!(
            automatic.passed(),
            "Source automatic MySQL value contract failed: {:?}",
            automatic.differences
        );
        self.observe_value_slot_applicable(automatic.evaluated);
        for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
            let raw = crate::protocols::replay::mysql::contracts::source_witness_from_record(
                &record, surface,
            )?;
            let slot = if surface == Surface::DependencyRequest {
                Slot::SqlValue(0)
            } else {
                Slot::SqlColumn(String::new())
            };
            self.record_value_witness(
                self.mysql_metadata(
                    case,
                    &identity,
                    &record,
                    (surface, slot),
                    TargetRole::Unavailable,
                    clocks,
                ),
                &raw,
                None,
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod global_tests;
