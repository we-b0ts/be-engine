//! Application binding to the independent recording writer.
pub(super) use traffic_recorder::{CaptureOptions, RecordEnvelope, RecorderWriter};

#[cfg(test)]
#[path = "writer/tests.rs"]
mod tests;
