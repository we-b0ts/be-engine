//! Native Source payload projection with host-owned secret access.
use anyhow::Result;
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSide {
    Request,
    Response,
}

pub trait EvidenceSecrets: Send + Sync {
    fn unseal_text<'a>(&self, label: &str, value: &'a str) -> Result<Cow<'a, str>>;
}
