//! PREPARE metadata is scoped to immutable Source inventory and Replay policy.
use super::*;
use std::mem::size_of;

const MAX_ENTRIES: usize = 128;
const MAX_ENTRY_BYTES: usize = 64 * 1024;

struct ScopeRef<'a> {
    case: Option<&'a str>,
    identity: &'a ReplaySessionIdentity,
    admission_epoch: u64,
    inventory_len: usize,
    policy: Option<&'a str>,
}

#[derive(Debug)]
struct Scope {
    case: Option<String>,
    identity: ReplaySessionIdentity,
    admission_epoch: u64,
    inventory_len: usize,
    policy: Option<String>,
}

#[derive(Debug, Default)]
pub(super) struct Cache {
    scope: Option<Scope>,
    entries: HashMap<String, Arc<StatementMetadata>>,
}

impl Cache {
    fn prepare_scope(&mut self, scope: ScopeRef<'_>) {
        if self.scope.as_ref().is_some_and(|previous| {
            previous.case.as_deref() == scope.case
                && &previous.identity == scope.identity
                && previous.admission_epoch == scope.admission_epoch
                && previous.inventory_len == scope.inventory_len
                && previous.policy.as_deref() == scope.policy
        }) {
            return;
        }
        self.entries.clear();
        self.scope = Some(Scope {
            case: scope.case.map(str::to_owned),
            identity: scope.identity.clone(),
            admission_epoch: scope.admission_epoch,
            inventory_len: scope.inventory_len,
            policy: scope.policy.map(str::to_owned),
        });
    }

    fn insert(&mut self, sql: &str, metadata: &Arc<StatementMetadata>) {
        let charge = metadata.columns.iter().fold(
            sql.len().saturating_add(
                metadata
                    .columns
                    .capacity()
                    .saturating_mul(size_of::<RecordedMysqlColumn>()),
            ),
            |bytes, column| {
                [
                    Some(&column.name),
                    Some(&column.family),
                    Some(&column.sql_type),
                    column.database.as_ref(),
                    column.table.as_ref(),
                    column.table_alias.as_ref(),
                    column.column.as_ref(),
                ]
                .into_iter()
                .flatten()
                .fold(bytes, |bytes, value| bytes.saturating_add(value.capacity()))
            },
        );
        if charge > MAX_ENTRY_BYTES {
            return;
        }
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(sql.to_owned(), Arc::clone(metadata));
    }
}

impl ReplayState {
    #[cfg(test)]
    pub(in crate::replay) fn statement_metadata(
        &mut self,
        identity: &ReplaySessionIdentity,
        sql: &str,
    ) -> StatementMetadata {
        let case = self.active_case_id.clone();
        (*self.statement_metadata_in_case(case.as_deref(), identity, sql)).clone()
    }

    pub(in crate::replay::mysql) fn statement_metadata_in_case(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        sql: &str,
    ) -> Arc<StatementMetadata> {
        let scope = ScopeRef {
            case,
            identity,
            admission_epoch: self.admission_epoch,
            inventory_len: self.protocols.mysql.exchanges.len(),
            policy: self
                .replay_policy
                .as_ref()
                .map(|policy| policy.fingerprint()),
        };
        let cache = &mut self.protocols.mysql.statement_metadata;
        cache.prepare_scope(scope);
        if let Some(metadata) = cache.entries.get(sql) {
            return Arc::clone(metadata);
        }
        let metadata = Arc::new(self.resolve_statement_metadata(case, identity, sql));
        self.protocols
            .mysql
            .statement_metadata
            .insert(sql, &metadata);
        metadata
    }

    fn resolve_statement_metadata(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        sql: &str,
    ) -> StatementMetadata {
        let normalized_sql = normalize_sql(sql);
        let param_count = count_sql_placeholders(sql);
        let select_hint = candidates::select_hint(sql);
        let mut semantic_target = None;
        let mut direct_projection = None;
        for source in [ReplaySource::Case, ReplaySource::Startup] {
            let candidates = self.protocols.mysql.candidates.select(
                &self.protocols.mysql.exchanges,
                source,
                case,
                identity,
                None,
            );
            for (project_columns, semantic) in [(false, false), (true, false), (false, true)] {
                for index in candidates.iter().copied() {
                    let exchange = &self.protocols.mysql.exchanges[index];
                    if !exchange.source.matches_scope(source)
                        || !active_case_matches(case, exchange)
                        || !identity_matches_exchange(identity, &exchange.identity)
                        || !self.protocols.mysql.candidates.permits_select(
                            index,
                            select_hint.as_ref(),
                            !project_columns && !semantic,
                        )
                    {
                        continue;
                    }
                    if !project_columns
                        && !semantic
                        && matches!(
                            exchange.record.command.as_str(),
                            "COM_QUERY" | "COM_STMT_EXECUTE"
                        )
                        && self.replay_policy.as_ref().is_some_and(|policy| {
                            policy.request_contracts.mysql_fields_metadata_matches(
                                case,
                                identity,
                                &exchange.record,
                                sql,
                            ) || policy.mysql_sql_values_metadata_matches(&MysqlPolicyContext {
                                request_times: crate::replay::assertion::RequestTimes {
                                    source: contracts::source_started(&exchange.record),
                                    target: None,
                                },
                                case_id: case,
                                identity,
                                command: "COM_STMT_EXECUTE",
                                recorded_sql: exchange.record.sql.as_deref(),
                                sql: Some(sql),
                                recorded: exchange.record.params.as_deref(),
                                actual: None,
                            })
                        })
                    {
                        return StatementMetadata::new(
                            param_count,
                            exchange.record.response.columns.clone(),
                        );
                    }
                    if semantic {
                        let Some(actual) = semantic_target
                            .get_or_insert_with(|| {
                                self.protocols.mysql.sql_cache.get(sql).metadata()
                            })
                            .as_ref()
                        else {
                            continue;
                        };
                        let Some(recorded_sql) = exchange.record.sql.as_deref() else {
                            continue;
                        };
                        let Some(recorded) = self
                            .protocols
                            .mysql
                            .sql_cache
                            .get(recorded_sql)
                            .bind(&exchange.record.command, exchange.record.params.as_deref())
                        else {
                            continue;
                        };
                        if let Some(columns) =
                            projection::semantic_columns(&exchange.record, &recorded, actual)
                        {
                            return StatementMetadata::new(param_count, columns);
                        }
                        continue;
                    }
                    if project_columns {
                        if let Some(columns) = direct_projection
                            .get_or_insert_with(|| {
                                projection::Query::prepare("COM_QUERY", sql, None)
                            })
                            .as_mut()
                            .and_then(|projection| projection.statement_columns(&exchange.record))
                        {
                            return StatementMetadata::new(param_count, columns);
                        }
                        continue;
                    }
                    let Some(recorded_sql) = exchange.record.sql.as_deref() else {
                        continue;
                    };
                    let matches = match exchange.record.command.as_str() {
                        "COM_STMT_EXECUTE" => {
                            normalize_sql(recorded_sql) == normalized_sql
                                || sql_match::prepared_metadata_matches(&exchange.record, sql)
                        }
                        "COM_QUERY" => sql_match::metadata_matches(sql, recorded_sql),
                        _ => false,
                    };
                    if matches {
                        return StatementMetadata::new(
                            param_count,
                            direct_projection
                                .get_or_insert_with(|| {
                                    projection::Query::prepare("COM_QUERY", sql, None)
                                })
                                .as_mut()
                                .and_then(|projection| {
                                    projection.statement_columns(&exchange.record)
                                })
                                .unwrap_or_else(|| exchange.record.response.columns.clone()),
                        );
                    }
                }
            }
        }
        StatementMetadata::new(
            param_count,
            builtin_response(sql, identity.database.as_deref())
                .map_or_else(Vec::new, |r| r.columns),
        )
    }
}
