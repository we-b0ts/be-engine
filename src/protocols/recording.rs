//! Application bindings for native recording evidence and completion.
pub(crate) mod async_api;

pub(crate) mod background;
pub(crate) mod events;
pub(crate) mod http;
pub(crate) mod kafka;
pub(crate) mod memcached;
pub(crate) mod motan;
mod recorder;
pub(crate) mod request;
pub(crate) mod summary;
pub(crate) mod tail;
