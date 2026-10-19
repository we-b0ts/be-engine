//! Interaction publication ownership and dependency activity snapshots.

use super::ActiveCaseRegistry;
use crate::recorder::CaseInvalidation;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

/// Commit ownership is separate from accepting new dependency attribution.
/// Acquiring this lock starts the final publication transaction. A lease loss
/// ordered before it is retained; a loss ordered after it cannot revoke that
/// already-linearized transaction. The owner holds the lock through disk publish.
#[derive(Debug, Default)]
pub(crate) struct InteractionPublication {
    state: tokio::sync::Mutex<InteractionPublicationState>,
}

#[derive(Debug, Default)]
pub(crate) struct InteractionPublicationState {
    pub(crate) invalidation: Option<CaseInvalidation>,
    pub(crate) finalized: bool,
}

impl InteractionPublication {
    pub(crate) async fn begin(&self) -> tokio::sync::MutexGuard<'_, InteractionPublicationState> {
        self.state.lock().await
    }

    fn invalidate(&self, invalidation: CaseInvalidation) -> bool {
        // There are no background holders: contention means the finalizer has
        // already crossed the commit barrier (or another loss already owns it).
        let Ok(mut state) = self.state.try_lock() else {
            return false;
        };
        if state.finalized {
            return false;
        }
        state.invalidation.get_or_insert(invalidation);
        true
    }
}

impl ActiveCaseRegistry {
    pub(crate) fn register_interaction_publication(
        &self,
        case_id: Uuid,
    ) -> Option<Arc<InteractionPublication>> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if !state.active.iter().any(|case| case.case.id == case_id) {
            return None;
        }
        Some(
            state
                .interaction_publications
                .entry(case_id)
                .or_default()
                .clone(),
        )
    }

    pub(crate) fn invalidate_interaction_reservation(
        &self,
        case_id: Option<Uuid>,
        invalidation: CaseInvalidation,
    ) -> bool {
        let publication = {
            let state = self.state.lock().expect("active case registry poisoned");
            let case_id = case_id.or_else(|| match state.active.as_slice() {
                [case] => Some(case.case.id),
                _ => None,
            });
            case_id.and_then(|id| state.interaction_publications.get(&id).cloned())
        };
        publication.is_some_and(|publication| publication.invalidate(invalidation))
    }

    pub(crate) fn dependency_activity(&self, case_id: Uuid) -> Option<(usize, Instant)> {
        self.state
            .lock()
            .expect("active case registry poisoned")
            .active
            .iter()
            .find(|case| case.case.id == case_id)
            .map(|case| case.dependencies.snapshot())
    }
    pub(crate) fn has_case(&self, case_id: Uuid) -> bool {
        self.state
            .lock()
            .expect("active case registry poisoned")
            .active
            .iter()
            .any(|case| case.case.id == case_id)
    }
}
