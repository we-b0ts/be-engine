//! Primary case publication ownership and dependency activity snapshots.

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
pub struct CasePublication {
    state: tokio::sync::Mutex<CasePublicationState>,
}

#[derive(Debug, Default)]
pub struct CasePublicationState {
    pub invalidation: Option<CaseInvalidation>,
    pub finalized: bool,
}

impl CasePublication {
    pub async fn begin(&self) -> tokio::sync::MutexGuard<'_, CasePublicationState> {
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

    pub(super) fn invalidate_shutdown(
        &self,
        invalidation: CaseInvalidation,
    ) -> Option<CaseInvalidation> {
        let mut state = self.state.try_lock().ok()?;
        if state.finalized {
            return None;
        }
        Some(state.invalidation.get_or_insert(invalidation).clone())
    }
}

impl ActiveCaseRegistry {
    pub fn register_case_publication(&self, case_id: Uuid) -> Option<Arc<CasePublication>> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if !state.active.iter().any(|case| case.case.id == case_id) {
            return None;
        }
        Some(state.case_publications.entry(case_id).or_default().clone())
    }

    pub fn invalidate_interaction_reservation(
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
            case_id.and_then(|id| state.case_publications.get(&id).cloned())
        };
        publication.is_some_and(|publication| publication.invalidate(invalidation))
    }

    pub fn dependency_activity(&self, case_id: Uuid) -> Option<(usize, Instant)> {
        self.state
            .lock()
            .expect("active case registry poisoned")
            .active
            .iter()
            .find(|case| case.case.id == case_id)
            .map(|case| case.dependencies.snapshot())
    }
    pub fn has_case(&self, case_id: Uuid) -> bool {
        self.state
            .lock()
            .expect("active case registry poisoned")
            .active
            .iter()
            .any(|case| case.case.id == case_id)
    }
}
