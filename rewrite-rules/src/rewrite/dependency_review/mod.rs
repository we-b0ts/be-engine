//! Immutable Source membership and rule-bound ownership proofs.
pub use traffic_rewrite_model::rewrite::dependency_review::{decisions, model};
pub mod client_abort;
pub mod rules;
pub mod socketio_tail;
pub mod source;
mod case_defaults {
    pub use traffic_engine_evidence::attribution_defaults::load;
}
