//! Source change analysis, source review and stage-bound quality receipts.
pub use traffic_engine::{e2e_run, internal_runtime, repository};
pub use traffic_rewrite_model::rewrite::RewriteWorkScope;
pub mod fingerprint {
    pub use traffic_engine::execution_identity::*;
}
pub mod evidence;
pub mod model;
pub mod quality;
pub mod scan;
pub mod source_diff;

pub mod final_inputs;

pub mod candidate;
