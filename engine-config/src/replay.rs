pub const DEFAULT_REPLAY_STREAM_INTERVAL_CAP_MS: u64 = 5;

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStreamTiming {
    Fast,
    #[default]
    Recorded,
}

pub mod loading_config;
pub use loading_config::*;
pub const DEFAULT_REPLAY_CASE_DEPENDENCY_POST_RESPONSE_WINDOW_MS: u64 = 0;
pub const DEFAULT_REPLAY_CASE_NO_PROGRESS_TIMEOUT_MS: u64 = 2_000;
