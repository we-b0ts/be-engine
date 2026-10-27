//! Pure value semantics shared by policy, protocol adapters, and assertions.
pub(crate) mod delivery;
pub(crate) mod encoded;
pub(crate) mod generated;
pub(crate) mod global;
pub(crate) mod global_protocol;
pub(crate) mod http_headers;
pub(crate) mod identities;
pub(crate) mod json;
pub(crate) mod pre_match;
pub(crate) mod redis_scalar;
pub(crate) mod time;
pub(crate) mod time_copies;
pub(crate) mod url_query;
