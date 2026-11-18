
use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    Next {
        api: Option<String>,
        source_route: Option<String>,
        #[serde(default)]
        execution_mode: RewriteExecutionMode,
    },
    TargetQuality {
        api: String,
        gate_id: String,
        hardcode_ai_verified: Vec<String>,
    },
}
