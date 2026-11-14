//! Result rows are delivery evidence; session and projection facts stay resident.
use super::*;
#[cfg(test)]
use crate::DependencyExchangeOutcome;

impl ReplayState {
    pub(in crate::replay) fn visit_global_mysql_unused(
        &self,
        visitor: &mut dyn FnMut(serde_json::Value) -> Result<()>,
    ) -> Result<()> {
        for item in self.mysql_unused_iter(ReplaySource::Startup, None) {
            visitor(serde_json::to_value(item)?)?;
        }
        Ok(())
    }
    pub(in crate::replay) fn global_mysql_unused_count(&self) -> usize {
        if let Some(count) = self.mysql.global_report_count() {
            return count + self.global_mysql_extra_unused_count();
        }
        self.mysql_unused_iter(ReplaySource::Startup, None).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn exchange() -> RecordedMysqlExchange {
        serde_json::from_value(json!({
            "command":"COM_QUERY", "response":{
                "status":"resultset",
                "columns":[{"name":"id","family":"integer","sql_type":"INT"}],
                "rows":[[{"kind":"integer","value":1}]]
            }
        }))
        .unwrap()
    }

    #[test]
    fn diagnostic_row_count_uses_resident_shape_without_loading_payloads() {
        let mut record = exchange();
        assert_eq!(record.result_row_count(), Some(1));
        record.response.rows.clear();
        assert_eq!(record.result_row_count(), Some(0));
        record.response.row_shape = Some((7, true));
        assert_eq!(record.result_row_count(), Some(7));
    }

    #[test]
    fn incomplete_or_malformed_results_do_not_claim_an_exact_row_count() {
        let mut record = exchange();
        record.response.rows_truncated = true;
        assert_eq!(record.result_row_count(), None);
        record.response.rows_truncated = false;
        record.outcome = DependencyExchangeOutcome::ClientTerminated;
        assert_eq!(record.result_row_count(), None);
        record.outcome = DependencyExchangeOutcome::Response;
        record.response.status = "ok".into();
        assert_eq!(record.result_row_count(), None);
        record.response.status = "resultset".into();
        record.response.row_shape = Some((1, false));
        assert_eq!(record.result_row_count(), None);
        record.response.row_shape = None;
        record.response.rows[0].clear();
        assert_eq!(record.result_row_count(), None);
    }
}
