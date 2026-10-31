//! Result rows are delivery evidence; session and projection facts stay resident.
use super::*;
use crate::DependencyExchangeOutcome;

impl RecordedMysqlExchange {
    /// Exact rows in a complete result, including resident shape metadata after
    /// lazy payload detachment. Partial or malformed results have no exact count.
    pub(in crate::replay) fn result_row_count(&self) -> Option<usize> {
        let response = &self.response;
        (self.outcome == DependencyExchangeOutcome::Response
            && response.status == "resultset"
            && !response.rows_truncated
            && response.valid_row_widths())
        .then(|| {
            response
                .row_shape
                .map_or(response.rows.len(), |(count, _)| count)
        })
    }
}

impl RecordedMysqlResponse {
    pub(in crate::replay) fn detach(&mut self, evidence: crate::dependency_index::RecordRef) {
        self.row_shape = Some((
            self.rows.len(),
            self.rows.iter().all(|row| row.len() == self.columns.len()),
        ));
        self.rows = Vec::new();
        self.evidence = Some(evidence);
    }

    pub(super) fn valid_row_widths(&self) -> bool {
        self.row_shape.map_or_else(
            || self.rows.iter().all(|row| row.len() == self.columns.len()),
            |(_, valid)| valid,
        )
    }

    pub(super) fn no_rows(&self) -> bool {
        self.row_shape
            .map_or_else(|| self.rows.is_empty(), |(count, _)| count == 0)
    }

    pub(super) fn materialize(&self) -> Result<Self> {
        let Some(evidence) = &self.evidence else {
            return Ok(self.clone());
        };
        #[derive(Deserialize)]
        struct Envelope {
            response: RecordedMysqlResponse,
        }
        Ok(evidence.load::<Envelope>()?.response)
    }
}

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
        if let Some(count) = self.mysql.global_report_usage().count() {
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
