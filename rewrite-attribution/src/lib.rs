//! Source ownership admission, proofs and frozen attribution identities.
pub use traffic_engine::*;
pub mod model;
use traffic_rewrite_rules::rewrite::dependency_review::{decisions, rules, source};
mod case_defaults {
    pub use traffic_engine::attribution_defaults::{load, load_for_replay};
}
pub mod admission;
pub mod snapshot;
pub mod validation;

pub use traffic_rewrite_model::rewrite::{api_selector, verification_obligations};
pub mod action {
    pub use traffic_rewrite_model::rewrite::action::*;
}
pub mod queries;

pub mod impact;
pub mod submission;

pub use traffic_rewrite_model::rewrite::inventory;
pub mod fingerprint {
    pub use traffic_engine::execution_identity::*;
}
pub mod batch_verification;
pub mod verification;
pub mod workflow_verification;
