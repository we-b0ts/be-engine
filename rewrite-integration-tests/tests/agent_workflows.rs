//! Public agent commands and coordinator transitions over shared role state.
use std::path::Path;
pub use traffic_engine::execution_identity as fingerprint;
pub use traffic_engine::internal_runtime;
use traffic_rewrite::testing::RewriteStore;
pub use traffic_rewrite::*;
pub use traffic_rewrite_model::rewrite::model;
use traffic_rewrite_model::rewrite::model::RewriteState;
use traffic_rewrite_review::source_diff;

mod api_selector {
    use super::{RewriteState, RewriteWorkScope};
    pub use traffic_rewrite_model::rewrite::api_selector::public_api;
    pub fn work_scope(_state: &RewriteState, api: &str) -> RewriteWorkScope {
        RewriteWorkScope::Api {
            api: public_api(api).into(),
        }
    }
}
mod workflow_test_support {
    pub use traffic_engine::test_support::install_source_snapshot;
}
mod worker {
    pub use traffic_rewrite::testing::confirm_current_worker as confirm_current_for_test;
    pub use traffic_rewrite::{RewriteWorkerTransferOptions, transfer_rewrite_worker as transfer};
    pub mod model {
        pub use traffic_rewrite_model::rewrite::worker::model::*;
    }
    pub mod runtime {
        pub use traffic_rewrite::testing::{
            worker_acceptance_ready as acceptance_ready, worker_coverage as coverage,
            worker_scopes as scopes,
        };
        pub use traffic_rewrite::{RewriteWorkerReportOptions, report_rewrite_worker as report};
    }
    pub mod tests {
        pub use traffic_rewrite::testing::{
            configured_target, implementation_state_with_inventory,
        };
    }
}
mod review {
    pub use traffic_rewrite::export_rewrite_integration_batch as export_batch;
}
mod repository_analysis {
    pub use traffic_rewrite::RepositoryAnalysisSnapshot;
}
#[path = "agents/expert.rs"]
mod expert;
#[path = "agents/implementer.rs"]
mod implementer;
