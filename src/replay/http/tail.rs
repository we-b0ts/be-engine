//! Resolve finite tail obligations using immutable HTTP exchange identities.
use super::*;
use anyhow::ensure;
use uuid::Uuid;

impl ReplayState {
    pub(in crate::replay) fn http_case_exchange_indices(
        &self,
        case_id: &str,
        selected: &BTreeSet<Uuid>,
    ) -> Result<BTreeMap<Uuid, usize>> {
        let mut indices = BTreeMap::new();
        for (index, exchange) in self.http_exchanges.iter().enumerate() {
            if exchange.case_id.as_deref() != Some(case_id) {
                continue;
            }
            let Some(id) = exchange.record.id.as_deref().and_then(|id| id.parse().ok()) else {
                continue;
            };
            if selected.contains(&id) {
                // Explicit cross-case rules may change the derived scope, but
                // cannot change the physical Source case or exchange identity.
                ensure!(
                    indices.insert(id, index).is_none(),
                    "HTTP tail reference is ambiguous in its Case semantic dependencies"
                );
            }
        }
        ensure!(
            indices.len() == selected.len(),
            "HTTP tail reference is absent from its Case semantic dependencies"
        );
        Ok(indices)
    }

    pub(in crate::replay) fn http_exchange_status(
        &self,
        index: usize,
    ) -> Option<super::super::ReplayExchangeStatus> {
        self.http_exchanges
            .get(index)
            .map(|exchange| exchange.status)
    }
}
