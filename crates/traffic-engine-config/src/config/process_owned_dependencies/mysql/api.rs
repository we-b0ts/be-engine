//! API-origin reads and single-row UPDATEs; ordinary process rules remain read-only.
use super::*;

impl MysqlBackgroundSelector {
    pub fn validate_api(&self) -> Result<()> {
        if self.validate().is_ok() {
            return Ok(());
        }
        super::super::validate_single_line("MySQL target host", &self.target_host, 253)?;
        ensure!(
            self.target_host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
                && self.target_port > 0,
            "invalid MySQL endpoint"
        );
        super::super::validate_single_line("MySQL database", &self.database, 64)?;
        super::super::validate_single_line("MySQL username", &self.username, 128)?;
        super::super::validate_single_line("MySQL SQL selector", &self.sql, 8192)?;
        TableMatcher::new(
            &self.tables,
            &self.table_patterns,
            self.table_series.as_ref(),
        )?;
        let template = self.api_template().ok_or_else(|| anyhow::anyhow!("API MySQL selector requires a bounded SELECT or single-table literal UPDATE with WHERE"))?;
        ensure!(
            template
                .iter()
                .filter(|t| **t == Token::Placeholder)
                .count()
                <= 16,
            "too many SQL value positions"
        );
        Ok(())
    }

    pub fn api_template(&self) -> Option<Vec<Token>> {
        if let Some(template) = self.template() {
            return Some(template);
        }
        if !self.sql.contains("{{table}}") || self.sql.contains(TABLE_MARKER) {
            return None;
        }
        let ts = tokens(&self.sql.replace("{{table}}", TABLE_MARKER))?;
        if !ts.first()?.is("update") || !ts.get(1)?.is(TABLE_MARKER) || !ts.get(2)?.is("set") {
            return None;
        }
        let where_pos = ts.iter().position(|t| t.is("where"))?;
        if ts.iter().filter(|t| t.is("update")).count() != 1
            || ts.iter().any(|t| {
                [
                    "select",
                    "join",
                    "union",
                    "into",
                    "order",
                    "limit",
                    "returning",
                    "@",
                    "@@",
                    ":=",
                    "{",
                    "}",
                ]
                .iter()
                .any(|s| t.is(s))
            })
        {
            return None;
        }
        let mut pos = 3;
        while pos < where_pos {
            if !matches!(ts.get(pos)?, Token::Word(_) | Token::Identifier(_)) {
                return None;
            }
            pos += 1;
            if ts.get(pos)?.is(".") {
                pos += 1;
                if !matches!(ts.get(pos)?, Token::Word(_) | Token::Identifier(_)) {
                    return None;
                }
                pos += 1;
            }
            if !ts.get(pos)?.is("=") {
                return None;
            }
            pos += 1;
            if !ts.get(pos)?.is_value() && *ts.get(pos)? != Token::Placeholder {
                return None;
            }
            pos += 1;
            if pos == where_pos {
                break;
            }
            if !ts.get(pos)?.is(",") {
                return None;
            }
            pos += 1;
        }
        if pos != where_pos || pos == 3 {
            return None;
        }
        // Table expansions may only occupy complete identifiers.
        if ts.iter().filter(|t| t.is(TABLE_MARKER)).count() != self.sql.matches("{{table}}").count()
        {
            return None;
        }
        Some(ts)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn matches_api_query(
        &self,
        host: Option<&str>,
        port: Option<u16>,
        database: Option<&str>,
        username: Option<&str>,
        command: &str,
        sql: Option<&str>,
    ) -> bool {
        if self.matches_query(host, port, database, username, command, sql) {
            return true;
        }
        if !host.is_some_and(|h| h.eq_ignore_ascii_case(&self.target_host))
            || port != Some(self.target_port)
            || database != Some(self.database.as_str())
            || username != Some(self.username.as_str())
            || !matches!(command, "COM_QUERY" | "COM_STMT_EXECUTE")
        {
            return false;
        }
        let (Some(template), Some(actual)) = (self.api_template(), sql.and_then(tokens)) else {
            return false;
        };
        if !template[0].is("update") {
            return false;
        }
        let Some(Token::Word(table)) = actual.get(1) else {
            return false;
        };
        let Ok(tables) = TableMatcher::new(
            &self.tables,
            &self.table_patterns,
            self.table_series.as_ref(),
        ) else {
            return false;
        };
        tables.matches(table)
            && instantiate(&template, table).is_some_and(|template| {
                template.len() == actual.len()
                    && template
                        .iter()
                        .zip(&actual)
                        .all(|(t, a)| t == a || (*t == Token::Placeholder && a.is_value()))
            })
    }
}
