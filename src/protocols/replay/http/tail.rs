//! Resolve finite tail obligations using immutable HTTP exchange identities.
use super::*;
use anyhow::ensure;
use uuid::Uuid;

impl ReplayState {
    pub(crate) fn http_case_exchange_indices(
        &self,
        case_id: &str,
        selected: &BTreeSet<Uuid>,
    ) -> Result<BTreeMap<Uuid, usize>> {
        let mut indices = BTreeMap::new();
        for (index, exchange) in self.protocols.http_exchanges.iter().enumerate() {
            if exchange.case_id.as_deref() != Some(case_id) {
                continue;
            }
            let Some(id) = exchange
                .record
                .native
                .id
                .as_deref()
                .and_then(|id| id.parse().ok())
            else {
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

    /// Only explicitly shared initialization can remain unstarted at case end.
    /// Its immutable Source identity stays visible, and an actual async HTTP
    /// completion selector always keeps its ordinary finite obligation.
    pub(crate) fn http_shared_initialization(
        &self,
        index: usize,
        completion: &[crate::policy::AsyncHttpEnd],
    ) -> bool {
        self.protocols
            .http_exchanges
            .get(index)
            .is_some_and(|exchange| {
                exchange.shared_origin.is_some()
                    && !completion.iter().any(|end| {
                        exchange
                            .record
                            .native
                            .method
                            .eq_ignore_ascii_case(&end.method)
                            && exchange.identity.target.host
                                == crate::replay::normalize_host(&end.endpoint.host)
                            && exchange.identity.target.port == end.endpoint.port
                            && uri_path_only(&exchange.record.native.uri) == end.path
                    })
            })
    }

    pub(crate) fn http_exchange_status(
        &self,
        index: usize,
    ) -> Option<crate::replay::ReplayExchangeStatus> {
        self.protocols.http_exchanges.get(index).map(|exchange| {
            if exchange.status == crate::replay::ReplayExchangeStatus::Responding
                && exchange
                    .lifecycle_prefix
                    .as_ref()
                    .is_some_and(|prefix| prefix.is_complete())
            {
                crate::replay::ReplayExchangeStatus::AwaitingClientTermination
            } else {
                exchange.status
            }
        })
    }
}

#[cfg(test)]
mod tests;
