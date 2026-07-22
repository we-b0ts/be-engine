#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MysqlMaintenanceQuery {
    C3p0TableProbe,
    SelectOne,
}

const MAX_MAINTENANCE_QUERY_BYTES: usize = 128;

pub(crate) fn is_mysql_maintenance_exchange(command: &str, sql: Option<&str>) -> bool {
    command == "COM_PING"
        || (command == "COM_QUERY" && sql.and_then(classify_mysql_maintenance_query).is_some())
}

pub(crate) fn classify_mysql_maintenance_query(sql: &str) -> Option<MysqlMaintenanceQuery> {
    if sql.len() > MAX_MAINTENANCE_QUERY_BYTES {
        return None;
    }

    match normalize_fingerprint(sql).as_str() {
        "show full tables from `` like 'probablynot'" => {
            Some(MysqlMaintenanceQuery::C3p0TableProbe)
        }
        "select 1" => Some(MysqlMaintenanceQuery::SelectOne),
        _ => None,
    }
}

fn normalize_fingerprint(sql: &str) -> String {
    let mut normalized = String::with_capacity(sql.len());
    let mut last_was_space = false;
    for ch in sql.trim().chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                normalized.push(' ');
            }
            last_was_space = true;
        } else {
            normalized.push(ch.to_ascii_lowercase());
            last_was_space = false;
        }
    }

    let normalized = normalized.trim_end();
    normalized
        .strip_suffix(';')
        .map(str::trim_end)
        .unwrap_or(normalized)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_supported_maintenance_queries() {
        assert_eq!(
            classify_mysql_maintenance_query("SHOW FULL TABLES FROM `` LIKE 'PROBABLYNOT'"),
            Some(MysqlMaintenanceQuery::C3p0TableProbe)
        );
        assert_eq!(
            classify_mysql_maintenance_query("  SeLeCt\n1 ; "),
            Some(MysqlMaintenanceQuery::SelectOne)
        );

        for sql in [
            "SELECT 2",
            "SELECT 1 FROM business_table",
            "SHOW FULL TABLES FROM `app` LIKE 'PROBABLYNOT'",
            "SHOW TABLES",
        ] {
            assert_eq!(classify_mysql_maintenance_query(sql), None, "{sql}");
        }

        let oversized_query = format!("SELECT 1{}", " ".repeat(MAX_MAINTENANCE_QUERY_BYTES));
        assert_eq!(classify_mysql_maintenance_query(&oversized_query), None);
    }

    #[test]
    fn recognizes_protocol_ping_without_treating_other_commands_as_maintenance() {
        assert!(is_mysql_maintenance_exchange("COM_PING", None));
        assert!(is_mysql_maintenance_exchange("COM_QUERY", Some("SELECT 1")));
        assert!(!is_mysql_maintenance_exchange(
            "COM_STMT_EXECUTE",
            Some("SELECT 1")
        ));
        assert!(!is_mysql_maintenance_exchange("COM_QUIT", None));
    }
}
