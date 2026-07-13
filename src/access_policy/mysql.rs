use crate::access_policy::{AccessDecision, AccessEvaluation, decide};
use crate::config::{RecordingAccessPolicy, RecordingAccessRuleConfig, RecordingAccessRuleEffect};
use crate::mysql::access::{MysqlAccessAnalysis, MysqlTableRef, MysqlWrite};

#[derive(Debug, Clone, Copy)]
pub(crate) struct MysqlAccessContext<'a> {
    pub(crate) route_name: Option<&'a str>,
    pub(crate) target_host: Option<&'a str>,
    pub(crate) target_addr: Option<&'a str>,
    pub(crate) database: Option<&'a str>,
}

pub(crate) fn evaluate_mysql_access(
    policy: RecordingAccessPolicy,
    rules: &[RecordingAccessRuleConfig],
    analysis: &MysqlAccessAnalysis,
    context: MysqlAccessContext<'_>,
) -> AccessEvaluation {
    let base = decide(policy, analysis.class);
    if base != AccessDecision::Reject {
        return AccessEvaluation::from_decision(base);
    }

    rules
        .iter()
        .find(|rule| mysql_rule_matches(rule, analysis, context))
        .map(|rule| AccessEvaluation::allowed_by(rule.name()))
        .unwrap_or_else(|| AccessEvaluation::from_decision(AccessDecision::Reject))
}

fn mysql_rule_matches(
    rule: &RecordingAccessRuleConfig,
    analysis: &MysqlAccessAnalysis,
    context: MysqlAccessContext<'_>,
) -> bool {
    let RecordingAccessRuleConfig::Mysql {
        effect,
        operations,
        routes,
        targets,
        databases,
        tables,
        ..
    } = rule;
    *effect == RecordingAccessRuleEffect::Allow
        && matches_scope(routes, context.route_name)
        && matches_target(targets, context)
        && analysis.statements_complete
        && !analysis.writes.is_empty()
        && analysis.writes.iter().all(|write| {
            mysql_write_matches(write, operations, databases, tables, context.database)
        })
}

fn mysql_write_matches(
    write: &MysqlWrite,
    operations: &[crate::MysqlWriteOperation],
    databases: &[String],
    tables: &[String],
    default_database: Option<&str>,
) -> bool {
    write.complete
        && write
            .operation
            .is_some_and(|operation| operations.contains(&operation))
        && !write.tables.is_empty()
        && write
            .tables
            .iter()
            .all(|table| mysql_table_matches(table, databases, tables, default_database))
}

fn mysql_table_matches(
    table: &MysqlTableRef,
    databases: &[String],
    tables: &[String],
    default_database: Option<&str>,
) -> bool {
    table
        .database
        .as_deref()
        .or(default_database)
        .is_some_and(|database| databases.iter().any(|allowed| allowed == database))
        && tables.iter().any(|allowed| allowed == &table.table)
}

fn matches_scope(allowed: &[String], actual: Option<&str>) -> bool {
    allowed.is_empty()
        || actual.is_some_and(|actual| allowed.iter().any(|allowed| allowed == actual))
}

fn matches_target(allowed: &[String], context: MysqlAccessContext<'_>) -> bool {
    allowed.is_empty()
        || allowed.iter().any(|allowed| {
            context.target_host == Some(allowed.as_str())
                || context.target_addr == Some(allowed.as_str())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RecordingAccessRuleEffect;
    use crate::mysql::access::analyze_sql;
    use crate::mysql::operation::MysqlWriteOperation;

    fn rule(operations: Vec<MysqlWriteOperation>, tables: Vec<&str>) -> RecordingAccessRuleConfig {
        RecordingAccessRuleConfig::Mysql {
            name: "allow-request-log".to_string(),
            effect: RecordingAccessRuleEffect::Allow,
            operations,
            routes: vec!["audit-db".to_string()],
            targets: Vec::new(),
            databases: vec!["pluto".to_string()],
            tables: tables.into_iter().map(ToOwned::to_owned).collect(),
        }
    }

    fn context<'a>() -> MysqlAccessContext<'a> {
        MysqlAccessContext {
            route_name: Some("audit-db"),
            target_host: Some("mysql-log.internal"),
            target_addr: Some("mysql-log.internal:3306"),
            database: Some("pluto"),
        }
    }

    #[test]
    fn allows_only_a_complete_write_fully_matched_by_one_rule() {
        let rules = vec![rule(vec![MysqlWriteOperation::Insert], vec!["request_log"])];
        let allowed = evaluate_mysql_access(
            RecordingAccessPolicy::BlockKnownWrites,
            &rules,
            &analyze_sql("INSERT INTO request_log(message) VALUES ('ok')"),
            context(),
        );
        assert_eq!(allowed.decision, AccessDecision::Allow);
        assert_eq!(allowed.matched_rule.as_deref(), Some("allow-request-log"));

        for sql in [
            "UPDATE request_log SET message = 'no'",
            "INSERT INTO business_table(message) VALUES ('no')",
            "SELECT * FROM request_log FOR UPDATE",
        ] {
            let rejected = evaluate_mysql_access(
                RecordingAccessPolicy::BlockKnownWrites,
                &rules,
                &analyze_sql(sql),
                context(),
            );
            assert_eq!(rejected.decision, AccessDecision::Reject, "{sql}");
            assert!(rejected.matched_rule.is_none());
        }
    }

    #[test]
    fn requires_all_multi_statement_writes_to_match_the_same_rule() {
        let rules = vec![rule(
            vec![MysqlWriteOperation::Insert, MysqlWriteOperation::Update],
            vec!["request_log"],
        )];
        let allowed = analyze_sql(
            "INSERT INTO request_log(message) VALUES ('a'); UPDATE request_log SET message = 'b'",
        );
        assert_eq!(
            evaluate_mysql_access(
                RecordingAccessPolicy::BlockKnownWrites,
                &rules,
                &allowed,
                context(),
            )
            .decision,
            AccessDecision::Allow
        );

        let mixed = analyze_sql(
            "INSERT INTO request_log(message) VALUES ('a'); UPDATE users SET active = 1",
        );
        assert_eq!(
            evaluate_mysql_access(
                RecordingAccessPolicy::BlockKnownWrites,
                &rules,
                &mixed,
                context(),
            )
            .decision,
            AccessDecision::Reject
        );

        let unknown = analyze_sql("CUSTOM COMMAND; INSERT INTO request_log(message) VALUES ('a')");
        assert_eq!(
            evaluate_mysql_access(
                RecordingAccessPolicy::BlockKnownWrites,
                &rules,
                &unknown,
                context(),
            )
            .decision,
            AccessDecision::Reject
        );
    }

    #[test]
    fn requires_route_target_database_and_case_sensitive_table_match() {
        let mut target_rule = rule(vec![MysqlWriteOperation::Insert], vec!["RequestLog"]);
        let RecordingAccessRuleConfig::Mysql {
            routes, targets, ..
        } = &mut target_rule;
        routes.clear();
        targets.push("mysql-log.internal:3306".to_string());

        let analysis = analyze_sql("INSERT INTO `RequestLog`(message) VALUES ('ok')");
        assert_eq!(
            evaluate_mysql_access(
                RecordingAccessPolicy::BlockKnownWrites,
                &[target_rule.clone()],
                &analysis,
                context(),
            )
            .decision,
            AccessDecision::Allow
        );

        let wrong_database = MysqlAccessContext {
            database: Some("other"),
            ..context()
        };
        assert_eq!(
            evaluate_mysql_access(
                RecordingAccessPolicy::BlockKnownWrites,
                &[target_rule],
                &analysis,
                wrong_database,
            )
            .decision,
            AccessDecision::Reject
        );
    }
}
