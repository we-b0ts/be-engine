use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevalidationRound {
    pub remaining: BTreeSet<String>,
}
