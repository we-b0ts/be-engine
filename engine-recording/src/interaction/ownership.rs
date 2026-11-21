//! Recording ownership hooks; transport shutdown precedes dependency draining.

use crate::AppState;
use crate::recorder::CaseInvalidation;
use std::time::Duration;
use uuid::Uuid;

impl AppState {
    pub(crate) fn invalidate_interaction_reservation(
        &self,
        case_id: Option<Uuid>,
        invalidation: CaseInvalidation,
    ) -> bool {
        self.inner
            .active_cases
            .invalidate_interaction_reservation(case_id, invalidation)
    }

    pub(crate) async fn wait_for_interaction_case(&self, case_id: Uuid) {
        while self.inner.active_cases.has_case(case_id) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}
