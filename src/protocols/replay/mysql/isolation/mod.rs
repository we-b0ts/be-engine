//! Framework entry point for native MySQL isolation constraints.
#[cfg(test)]
use super::*;
pub(crate) use traffic_protocol_mysql::isolation_session::Registry;

#[cfg(test)]
pub(in crate::protocols::replay::mysql) mod tests;
