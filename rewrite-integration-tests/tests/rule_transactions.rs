//! Cross-library rule publication, recovery and concurrent Replay contracts.
use anyhow::Result;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};
pub use traffic_engine::execution_identity as fingerprint;
pub use traffic_engine::*;
pub use traffic_rewrite::testing::{
    RewriteStore, batch_execution_identity, dependency_attribution_snapshot,
};
pub use traffic_rewrite::*;
pub use traffic_rewrite_evidence::evidence_model;
pub use traffic_rewrite_model::rewrite::model;
pub use traffic_rewrite_runtime::traffic_operation;
mod evidence {
    pub use traffic_rewrite::testing::query_issue_evidence as query;
    pub use traffic_rewrite_evidence::evidence::*;
}
mod worker {
    pub use traffic_rewrite::{RewriteWorkerConfirmOptions, confirm_rewrite_worker as confirm};
    pub mod tests {
        pub use traffic_rewrite::testing::{
            configured_target, implementation_state_with_inventory,
        };
    }
    pub mod runtime {
        pub use traffic_rewrite::testing::worker_acceptance_ready as acceptance_ready;
    }
}
mod replay_admission {
    pub use traffic_rewrite::testing::replay_admitted as admitted;
}
mod rule_plans {
    pub use traffic_rewrite::testing::idle_rule_plan_action as idle_action;
}
mod dependency_review {
    pub use traffic_rewrite::testing::attribution_required_action as required_action;
}
mod verification_obligations {
    pub use traffic_rewrite::testing::request_capture;
    pub use traffic_rewrite_model::rewrite::verification_obligations::*;
}
mod workflow_test_support {
    pub use traffic_engine::test_support::*;
}
mod unified_rule;

use traffic_engine::policy::{PolicyRule, compile_policy};
use traffic_rewrite_model::rewrite::model::RewriteState;
mod inventory {
    pub use traffic_rewrite::testing::ownership_evidence_api as api_for_ownership_evidence_id;
}
