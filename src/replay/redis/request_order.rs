//! Redis uses the common arrival counter; retries retain their original index.
pub(super) use crate::replay::admission::RequestOrder;

#[cfg(test)]
mod tests;
