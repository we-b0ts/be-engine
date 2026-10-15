//! Result rows are delivery evidence; session and projection facts stay resident.
use super::*;

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
        for item in self.mysql_unused_iter(ReplaySource::Global, None) {
            visitor(serde_json::to_value(item)?)?;
        }
        Ok(())
    }
    pub(in crate::replay) fn global_mysql_unused_count(&self) -> usize {
        self.mysql_unused_iter(ReplaySource::Global, None).count()
    }
}
