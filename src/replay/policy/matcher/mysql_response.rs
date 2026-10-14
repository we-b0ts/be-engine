//! Select and account for explicit MySQL result timestamp policies.
use super::*;
use crate::replay::{RecordedMysqlExchange, RecordedMysqlResponse};

impl ReplayPolicyRuntime {
    pub(in crate::replay) fn shift_mysql_response(
        &self,
        case_id: Option<&str>,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        delivered: &RecordedMysqlResponse,
    ) -> Result<(RecordedMysqlResponse, Vec<String>)> {
        if record.outcome != crate::DependencyExchangeOutcome::Response
            || delivered.status != "resultset"
        {
            return Ok((delivered.clone(), vec![]));
        }
        let Some((case_id, case)) =
            case_id.and_then(|id| self.cases.get(id).map(|case| (id, case)))
        else {
            return Ok((delivered.clone(), vec![]));
        };
        let mut fields = BTreeMap::new();
        let mut ids = Vec::new();
        for rule in &self.loaded.document.dependency_rules {
            if rule.protocol != DependencyProtocol::Mysql
                || !rule_matches_case(rule, case)
                || !self.mysql_selectors.matches(
                    rule,
                    identity,
                    &record.command,
                    record.sql.as_deref(),
                )
            {
                continue;
            }
            let mysql = rule.mysql.as_ref().expect("validated MySQL rule");
            if mysql.response_time_shift.is_empty() {
                continue;
            }
            let count = fields.len();
            for (column, field) in &mysql.response_time_shift {
                // Validate the selected physical column on immutable evidence.
                // A proven target projection may omit that column entirely.
                crate::replay::mysql::time_shift::column_index(&record.response, column)?;
                if !delivered
                    .columns
                    .iter()
                    .any(|metadata| metadata.column.as_deref().unwrap_or(&metadata.name) == column)
                {
                    continue;
                }
                ensure!(
                    fields
                        .insert(column.clone(), field.preserved_values()?)
                        .is_none(),
                    "overlapping MySQL response time shift columns"
                );
            }
            if fields.len() > count {
                ids.push(rule.id.clone());
            }
        }
        if fields.is_empty() {
            return Ok((delivered.clone(), ids));
        }
        Ok((
            crate::replay::mysql::time_shift::shift_response(
                delivered,
                &fields,
                self.request_contracts.request_times(case_id),
            )?,
            ids,
        ))
    }

    pub(in crate::replay) fn commit_mysql_response_shift(&mut self, ids: &[String]) {
        for id in ids {
            let usage = self.usage.entry(id.clone()).or_default();
            usage.matches += 1;
            usage.time_validations += 1;
        }
    }
}
