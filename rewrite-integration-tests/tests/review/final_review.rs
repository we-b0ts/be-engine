//! Full final candidate admission and revalidation across coordinator services.
use super::*;
use std::collections::BTreeSet;
pub use traffic_rewrite::testing::review::{
    pre_revalidation_accepted_path as accepted_path, pre_revalidation_admit as admit,
    pre_revalidation_checked_path as checked_path,
    pre_revalidation_completion_current as completion_current, pre_revalidation_current as current,
    pre_revalidation_ready as ready, pre_revalidation_reconcile as reconcile,
    pre_revalidation_required_action as required_action,
};
use traffic_rewrite_review::final_inputs::context;
use traffic_rewrite_review::final_inputs::fingerprint as input_fingerprint;
#[path = "final_review/tests.rs"]
mod tests;
