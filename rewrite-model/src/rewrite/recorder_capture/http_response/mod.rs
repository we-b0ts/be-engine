use crate::rewrite::*;
use traffic_engine_config::HttpResponseRewriteRuleConfig;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseCaptureSpec {
    pub case_id: String,
    pub response_id: String,
    pub response_digest: String,
    pub rule: HttpResponseRewriteRuleConfig,
    #[serde(default)]
    pub pattern_checked: bool,
}
