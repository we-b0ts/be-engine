//! Shared CLI table bounds for MySQL read and SQL-time templates.
use clap::Args;

#[derive(Debug, Args)]
pub(super) struct MysqlTableArgs {
    /// Exact physical table name. Repeatable; requires {{table}} in SQL.
    #[arg(long = "table")]
    pub tables: Vec<String>,
    /// Table identifier pattern with one *, e.g. subtasks_*. Repeatable.
    #[arg(long = "table-pattern")]
    pub table_patterns: Vec<String>,
    #[arg(long, requires_all = ["table_start", "table_end"])]
    table_prefix: Option<String>,
    #[arg(long, requires = "table_prefix")]
    table_start: Option<u32>,
    #[arg(long, requires = "table_prefix")]
    table_end: Option<u32>,
    #[arg(long, default_value_t = 4)]
    table_width: usize,
}

impl MysqlTableArgs {
    pub(super) fn series(&self) -> Option<traffic_e2e::MysqlTableSeries> {
        self.table_prefix
            .as_ref()
            .map(|prefix| traffic_e2e::MysqlTableSeries {
                prefix: prefix.clone(),
                start: self.table_start.expect("clap requires table-start"),
                end: self.table_end.expect("clap requires table-end"),
                width: self.table_width,
            })
    }
}
