//! Worker feedback persistence is shared with the runtime service.
pub(crate) use traffic_rewrite_agents::journal::{lock, overlay, publish, publish_many};

#[cfg(test)]
mod tests;
