//! Application bindings for native recording evidence and completion.
pub(crate) mod async_api;

pub mod background;
pub mod events;
pub(crate) mod http;
mod recorder;
pub(crate) mod request;
pub(crate) mod summary;
pub(crate) mod tail;
