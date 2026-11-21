use crate::rewrite::*;
#[derive(Debug, Clone, Default, Serialize)]
pub struct RewriteCoordinationDetails {
    pub ready: BTreeMap<String, usize>,
    pub waiting: BTreeMap<String, usize>,
    pub completed: usize,
}

impl RewriteCoordinationDetails {
    pub fn pending(&self) -> usize {
        self.ready.values().sum()
    }
}
