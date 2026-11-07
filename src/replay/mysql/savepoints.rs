//! Connection-local Source/Target savepoint names, committed after delivery.
use super::*;
use crate::mysql::savepoint::{Command, Kind, parse};

#[derive(Debug)]
struct Binding {
    source: String,
    target: String,
    rolled_back: bool,
}

#[derive(Debug, Default)]
pub(super) struct Bindings {
    connection: Option<Uuid>,
    sequence: Option<u64>,
    names: Vec<Binding>,
}

pub(super) fn complete(record: &RecordedMysqlExchange) -> bool {
    matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        && record.outcome == crate::DependencyExchangeOutcome::Response
        && record.parse_warnings.is_empty()
        && record.params.as_ref().is_none_or(Vec::is_empty)
        && record.response.status == "ok"
        && record.response.error_code.is_none()
        && record.response.error_message.is_none()
        && record.response.affected_rows == Some(0)
        && record.response.last_insert_id == Some(0)
        && record.response.no_rows()
        && record.response.columns.is_empty()
        && !record.response.rows_truncated
        && record
            .server_status_before
            .zip(record.response.server_status)
            .is_some_and(|(before, after)| {
                before & 0x2009 == 1 && after & 0x2009 == 1 && before & 2 == after & 2
            })
}

impl Bindings {
    pub(super) fn preview_parsed(
        &self,
        record: &RecordedMysqlExchange,
        source: Option<&Command>,
        target: Option<&Command>,
        status: u16,
    ) -> Option<bool> {
        if source.is_none() && target.is_none() || !complete(record) {
            return None;
        }
        Some(
            (|| {
                let (source, target) = (source?, target?);
                if status & 0x2009 != 1
                    || source.kind != target.kind
                    || record.connection_id.is_none()
                    || record.query_sequence.is_none()
                    || self
                        .connection
                        .is_some_and(|c| Some(c) != record.connection_id)
                    || self
                        .sequence
                        .is_some_and(|s| record.query_sequence.is_none_or(|next| next <= s))
                {
                    return None;
                }
                let source_at = self.names.iter().position(|n| n.source == source.name);
                let target_at = self.names.iter().position(|n| n.target == target.name);
                match source.kind {
                    Kind::Create
                        if self.names.len() < 1024
                            && (source_at == target_at
                                || source_at.is_none()
                                    && target_at.is_some_and(|i| self.names[i].rolled_back)) =>
                    {
                        Some(())
                    }
                    Kind::Release | Kind::Rollback
                        if source_at.is_some() && source_at == target_at =>
                    {
                        Some(())
                    }
                    _ => None,
                }
            })()
            .is_some(),
        )
    }

    #[cfg(test)]
    fn preview(&self, record: &RecordedMysqlExchange, sql: &str, status: u16) -> Option<bool> {
        self.preview_parsed(
            record,
            record.sql.as_deref().and_then(parse).as_ref(),
            parse(sql).as_ref(),
            status,
        )
    }

    pub(super) fn observe(&mut self, record: &RecordedMysqlExchange, sql: &str) {
        if !matches!(record.response.status.as_str(), "ok" | "resultset") {
            return;
        }
        if matches!(
            normalize_sql(sql).as_str(),
            "begin" | "start transaction" | "commit" | "rollback"
        ) {
            *self = Self::default();
        } else if let (Some(source), Some(target)) =
            (record.sql.as_deref().and_then(parse), parse(sql))
        {
            self.connection = record.connection_id;
            self.sequence = record.query_sequence;
            let found = self.names.iter().position(|n| n.source == source.name);
            match (source.kind, found) {
                (Kind::Create, found) => {
                    if let Some(index) = found.or_else(|| {
                        self.names
                            .iter()
                            .position(|n| n.target == target.name && n.rolled_back)
                    }) {
                        self.names.remove(index);
                    }
                    self.names.push(Binding {
                        source: source.name,
                        target: target.name,
                        rolled_back: false,
                    });
                }
                (Kind::Release, Some(index)) => {
                    self.names.remove(index);
                }
                (Kind::Rollback, Some(index)) => {
                    self.names.truncate(index + 1);
                    self.names[index].rolled_back = true;
                }
                _ => {}
            }
        } else if record
            .server_status_before
            .zip(record.response.server_status)
            .is_some_and(|(before, after)| {
                before & 1 != 0 && after & 1 == 0 && before & 2 == after & 2
            })
        {
            *self = Self::default();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn control(sequence: u64, sql: &str) -> RecordedMysqlExchange {
        serde_json::from_value(json!({"command":"COM_QUERY","sql":sql,
            "connection_id":Uuid::from_u128(7),"query_sequence":sequence,
            "server_status_before":1,"response":{"status":"ok","server_status":1,
            "affected_rows":0,"last_insert_id":0}}))
        .unwrap()
    }

    #[test]
    fn speculative_candidates_do_not_bind_and_references_keep_identity_and_kind() {
        let mut names = Bindings::default();
        let create = control(1, "SAVEPOINT source");
        assert_eq!(names.preview(&create, "SAVEPOINT target", 3), Some(true));
        let release = control(2, "RELEASE SAVEPOINT source");
        assert_eq!(
            names.preview(&release, "RELEASE SAVEPOINT target", 3),
            Some(false)
        );
        names.observe(&create, "SAVEPOINT target");
        assert_eq!(
            names.preview(&release, "RELEASE SAVEPOINT other", 3),
            Some(false)
        );
        assert_eq!(
            names.preview(&release, "ROLLBACK TO SAVEPOINT target", 3),
            Some(false)
        );
        assert_eq!(
            names.preview(&release, "RELEASE SAVEPOINT target", 2),
            Some(false)
        );
        let mut foreign = release.clone();
        foreign.connection_id = Some(Uuid::from_u128(8));
        assert_eq!(
            names.preview(&foreign, "RELEASE SAVEPOINT target", 3),
            Some(false)
        );
        assert_eq!(
            names.preview(&release, "RELEASE SAVEPOINT target", 3),
            Some(true)
        );
        names.observe(&release, "RELEASE SAVEPOINT target");
        assert_eq!(
            names.preview(&control(3, "ROLLBACK TO source"), "ROLLBACK TO target", 3),
            Some(false)
        );
    }

    #[test]
    fn outer_rollback_discards_inner_names_and_completed_scope_names_can_be_reused() {
        let mut names = Bindings::default();
        names.observe(&control(1, "SAVEPOINT a"), "SAVEPOINT x");
        names.observe(&control(2, "SAVEPOINT b"), "SAVEPOINT y");
        names.observe(&control(3, "ROLLBACK TO a"), "ROLLBACK TO x");
        assert_eq!(
            names.preview(&control(4, "RELEASE SAVEPOINT b"), "RELEASE SAVEPOINT y", 3),
            Some(false)
        );
        assert_eq!(
            names.preview(&control(4, "SAVEPOINT c"), "SAVEPOINT x", 3),
            Some(true)
        );
        names.observe(&control(4, "SAVEPOINT c"), "SAVEPOINT x");
        assert_eq!(
            names.preview(&control(5, "RELEASE SAVEPOINT a"), "RELEASE SAVEPOINT x", 3),
            Some(false)
        );
        assert_eq!(
            names.preview(&control(5, "RELEASE SAVEPOINT c"), "RELEASE SAVEPOINT x", 3),
            Some(true)
        );
    }
}
