//! Cross-library delivery, receipt compatibility and batch integration contracts.
use anyhow::Result;
use std::{
    fs,
    path::{Path, PathBuf},
};
pub use traffic_engine::execution_identity as fingerprint;
pub use traffic_engine::*;
use traffic_rewrite::accept_rewrite_review as accept;
use traffic_rewrite::check_batch_rewrite_review as check_batch;
use traffic_rewrite::rework_rewrite_review as rework;
pub use traffic_rewrite::testing::RewriteStore;
use traffic_rewrite::testing::delivery_context as context;
use traffic_rewrite::testing::review::is_rework_wait;
use traffic_rewrite::testing::review::{
    integrated_admission_current as admission_current, integrated_gate as gate, integrated_path,
    integrated_required_action as required_action, integrated_terminal_current as terminal_current,
};
pub use traffic_rewrite::*;
use traffic_rewrite::{
    check_rewrite_pre_revalidation as check_pre_revalidation, show_rewrite_review as show,
};
pub use traffic_rewrite_model::rewrite::model;
use traffic_rewrite_model::rewrite::model::RewriteState;
use traffic_rewrite_review::{evidence, model::*, quality, source_diff};
mod action {
    pub use traffic_rewrite::testing::scoped_status as for_scoped_status;
    pub use traffic_rewrite::testing::workflow_status as for_status;
}
mod candidate {
    pub use traffic_rewrite::accept_rewrite_review as accept;
    pub use traffic_rewrite::testing::review::{
        candidate_accept_locked as accept_locked, candidate_batch_handoffs as batch_handoffs,
        candidate_current_handoff_scope as current_handoff_scope,
    };
    pub use traffic_rewrite_review::candidate::*;
}
mod integrated {
    pub use traffic_rewrite::testing::review::integrated_current as current;
}
#[path = "review/final_review.rs"]
mod final_review;
use final_review as pre_revalidation;
use traffic_rewrite::check_rewrite_review as check;
use traffic_rewrite::testing::workflow_state as test_state;
mod transition {
    pub use traffic_rewrite::testing::complete_replay_if_ready;
}

mod api_selector {
    pub use traffic_rewrite_model::rewrite::api_selector::public_api;
    pub fn work_scope(_: &super::RewriteState, api: &str) -> super::RewriteWorkScope {
        super::RewriteWorkScope::Api {
            api: public_api(api).into(),
        }
    }
}
mod worker {
    pub use traffic_rewrite::confirm_rewrite_worker as confirm;
    pub use traffic_rewrite::testing::{
        integrate_current_worker as integrate_current_for_test, worker_dispatch as dispatch_view,
    };
    pub mod model {
        pub use traffic_rewrite_model::rewrite::worker::model::*;
    }
    pub mod runtime {
        pub use traffic_rewrite::testing::worker_scoped as scoped;
        pub use traffic_rewrite::testing::{
            worker_acceptance_ready as acceptance_ready, worker_coverage as coverage,
            worker_observation as observation, worker_scopes as scopes,
        };
        pub use traffic_rewrite::{RewriteWorkerReportOptions, report_rewrite_worker as report};
    }
    pub mod scheduler {
        pub use traffic_rewrite::testing::worker_inventory as inventory;
    }
    pub mod tests {
        pub use traffic_rewrite::testing::workflow_issue as issue;
        pub use traffic_rewrite::testing::{
            configured_target, implementation_state_with_inventory,
        };
    }
}
mod workflow_test_support {
    pub use traffic_engine::test_support::*;
    pub use traffic_rewrite::testing::workflow_state as test_state;
}
mod inventory {
    pub use traffic_rewrite::testing::{
        complete_current_api as complete_current_and_advance, repair_api as api_for_repair,
    };
    pub use traffic_rewrite::testing::{
        install_api_inventory as install, resume_api_index as resume_at,
    };
    pub mod revalidation_round {
        pub use traffic_rewrite::testing::api_in_revalidation_round as contains;
        pub use traffic_rewrite::testing::finish_revalidation_api as finish;
    }
    pub use traffic_rewrite::testing::defer_completed_apis as defer_completed_for_target_change;
}
mod regression_scope {
    pub use traffic_rewrite::testing::api_is_skipped as is_skipped;
}
mod review {
    pub use traffic_rewrite::check_rewrite_review as check;
    pub mod batch {
        pub use traffic_rewrite::{
            RewriteIntegrationBatchOptions, check_rewrite_review_batch_file as check_file,
            export_rewrite_integration_batch as export,
        };
    }
}
mod engine_retry {
    pub use traffic_rewrite::testing::engine_retry_pending as pending;
}
#[path = "review/source_review.rs"]
mod tests;

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
#[path = "review/delivery_tests.rs"]
mod delivery_tests;
