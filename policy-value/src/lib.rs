//! Value-policy message preparation, comparison and authorized delivery.
pub mod diagnosis;
pub mod host;
pub mod inference;
mod message;
pub use message::{
    BindingRegistry, DocumentPolicy, DocumentPolicyPreparation, MessageSide,
    PreparedDocumentComparison, PreparedMessage, RenderedMessage, RuleBinding, StoredValue,
    ValueRule,
};

#[derive(Default)]
pub struct MessageRules {
    pub request: Vec<RuleBinding>,
    pub response: Vec<RuleBinding>,
    pub rebase_time: std::collections::BTreeSet<String>,
}

pub mod fields;

pub mod formats;
pub mod url_query;

pub mod identity;
pub mod scalar;
pub mod transformation;

/// Installed content decoding and value comparison services for carrier adapters.
#[derive(Clone, Copy)]
pub struct ExecutionContext<'a> {
    pub codecs: &'a traffic_value::codec::CodecRegistry,
    pub metadata: &'a dyn traffic_contract::compare::RuleMetadata,
}
