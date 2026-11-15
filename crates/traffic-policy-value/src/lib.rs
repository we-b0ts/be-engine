//! Value-policy message preparation, comparison and authorized delivery.
mod message;
pub use message::{
    BindingRegistry, DocumentPolicy, MessageSide, PreparedMessage, RenderedMessage, RuleBinding,
    ValueRule,
};

#[derive(Default)]
pub struct MessageRules {
    pub request: Vec<RuleBinding>,
    pub response: Vec<RuleBinding>,
    pub rebase_time: std::collections::BTreeSet<String>,
}
