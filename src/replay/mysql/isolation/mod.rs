//! Framework entry point for native MySQL isolation constraints.
#[cfg(test)]
use super::*;
pub(in crate::replay) use traffic_protocol_mysql::isolation_session::Registry;

#[cfg(test)]
pub(in crate::replay::mysql) mod tests;
