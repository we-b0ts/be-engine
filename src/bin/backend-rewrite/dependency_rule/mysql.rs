//! MySQL ownership CLI preserves ordinary SELECT rules and adds explicit API origins.
use super::*;

#[derive(Debug, Args)]
pub(super) struct MysqlDependencyRuleArgs {
    #[command(flatten)]
    common: DependencyRuleCommonArgs,
    #[arg(long)]
    target_host: String,
    #[arg(long, default_value_t = 3306)]
    target_port: u16,
    #[arg(long)]
    database: String,
    #[arg(long)]
    username: String,
    #[arg(
        long,
        help = "Bounded SELECT or API-origin UPDATE with {{table}} and ? for variable literals"
    )]
    sql: String,
    #[command(flatten)]
    table_scope: MysqlTableArgs,
    /// API origin JSON; request_body_json matches the trigger request BODY, not query/response.
    #[arg(long, value_name="JSON", requires="identity_value_index", value_parser=parse_source)]
    trigger_source: Option<traffic_e2e::ApiTriggerSource>,
    /// Zero-based '?' slot in SQL bound to the single captured positive integer identity.
    #[arg(long, requires = "trigger_source")]
    identity_value_index: Option<usize>,
    /// Include COMMIT/ROLLBACK only for complete source-proven transactions anchored by API-origin rules.
    #[arg(long, requires = "trigger_source")]
    include_transaction_boundaries: bool,
    /// Additional read-only SELECT selector JSON, admitted only inside a complete origin-anchored transaction.
    #[arg(long="transaction-member", requires="include_transaction_boundaries", value_parser=parse_member)]
    transaction_members: Vec<traffic_e2e::MysqlBackgroundSelector>,
}

fn parse_source(value: &str) -> std::result::Result<traffic_e2e::ApiTriggerSource, String> {
    serde_json::from_str(value).map_err(|e| format!("invalid trigger_source JSON: {e}"))
}

fn parse_member(value: &str) -> std::result::Result<traffic_e2e::MysqlBackgroundSelector, String> {
    serde_json::from_str(value).map_err(|e| format!("invalid transaction-member JSON: {e}"))
}

pub(super) fn options(args: MysqlDependencyRuleArgs) -> RewriteDependencyRulePlanOptions {
    let table_series = args.table_scope.series();
    let selector = traffic_e2e::MysqlBackgroundSelector {
        target_host: args.target_host,
        target_port: args.target_port,
        database: args.database,
        username: args.username,
        sql: args.sql,
        tables: args.table_scope.tables,
        table_patterns: args.table_scope.table_patterns,
        table_series,
    };
    let selector = if let Some(trigger_source) = args.trigger_source {
        RewriteDependencyRuleSelector::MysqlApiTriggered {
            selector: traffic_e2e::ApiTriggeredMysqlSelector {
                include_transaction_boundaries: args.include_transaction_boundaries,
                transaction_members: args.transaction_members,
                selector,
                trigger_source,
                identity_value_index: args
                    .identity_value_index
                    .expect("clap requires identity-value-index"),
            },
        }
    } else {
        RewriteDependencyRuleSelector::Mysql { selector }
    };
    dependency_rule_options(args.common, selector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: MysqlDependencyRuleArgs,
    }
    #[test]
    fn mysql_origin_flags_are_paired_and_choose_the_origin_planner() {
        let base = [
            "test",
            "--evidence-id",
            "current",
            "--ownership",
            "process-owned",
            "--name",
            "result",
            "--source-evidence",
            "jobs.py:finish reads its detached task result",
            "--target-host",
            "db.test",
            "--database",
            "app",
            "--username",
            "writer",
            "--table",
            "jobs",
            "--sql",
            "SELECT id FROM {{table}} WHERE id=?",
        ];
        let ordinary = TestCli::try_parse_from(base).unwrap();
        assert!(matches!(
            options(ordinary.args).selector,
            RewriteDependencyRuleSelector::Mysql { .. }
        ));
        let source = r#"{"kind":"api","method":"POST","path":"/jobs","request_body_json":{"/background":true},"capture":{}}"#;
        assert!(
            TestCli::try_parse_from(base.into_iter().chain(["--trigger-source", source])).is_err()
        );
        assert!(
            TestCli::try_parse_from(base.into_iter().chain(["--identity-value-index", "0"]))
                .is_err()
        );
        let origin = TestCli::try_parse_from(base.into_iter().chain([
            "--trigger-source",
            source,
            "--identity-value-index",
            "0",
        ]))
        .unwrap();
        assert!(matches!(
            options(origin.args).selector,
            RewriteDependencyRuleSelector::MysqlApiTriggered { .. }
        ));
    }
}
