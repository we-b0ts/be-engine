mod model;
mod motan;
mod order;
mod progress;
mod representative;
mod runtime;
mod store;
mod summary;
mod tasks;
mod upstream;
mod verification;

pub use progress::update_comparison_progress;
pub use representative::{
    ComparisonRepresentativeDifference, ComparisonRepresentativePolicyMismatch,
};
pub use runtime::{ComparisonRecordingRunOptions, run, run_with_duration, run_with_options};
pub(crate) use verification::resolve_comparison_case_dir;
pub use verification::{
    ComparisonVerificationApi, ComparisonVerificationApiCounts, ComparisonVerificationCase,
    ComparisonVerificationClassification, ComparisonVerificationCounts,
    ComparisonVerificationOptions, ComparisonVerificationOutcome, ComparisonVerificationReport,
    MatchedSourceObservation, verify_comparison_recording,
};
