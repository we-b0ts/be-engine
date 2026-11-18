use std::path::PathBuf;

pub use traffic_rewrite_model::rewrite::expert::model::ExpertAssignment;

pub use traffic_rewrite_model::rewrite::expert::model::ExpertDelivery;

pub use traffic_rewrite_model::rewrite::expert::model::RewriteExpertState;

pub use traffic_rewrite_model::rewrite::expert::model::RewriteExpertView;

pub use traffic_rewrite_model::rewrite::expert::model::RewriteExpertApiView;

pub use traffic_rewrite_model::rewrite::expert::model::RewriteExpertApiCommands;

pub use traffic_rewrite_model::rewrite::expert::model::RewriteExpertCommands;

pub use traffic_rewrite_model::rewrite::expert::model::RewriteExpertInventoryItem;

#[derive(Debug, Clone)]
pub struct RewriteExpertOptions {
    pub target_root: PathBuf,
    pub expert_id: String,
    pub agent_handle: String,
}

#[derive(Debug, Clone)]
pub struct RewriteExpertDeliveryOptions {
    pub expert: RewriteExpertOptions,
    pub api: String,
    pub report_id: String,
    pub recipient_handle: String,
}

#[derive(Debug, Clone)]
pub struct RewriteExpertPrepareOptions {
    pub target_root: PathBuf,
    pub expert_id: String,
    pub apis: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RewriteExpertCloseOptions {
    pub target_root: PathBuf,
    pub expert_id: String,
    pub agent_handle: Option<String>,
}
