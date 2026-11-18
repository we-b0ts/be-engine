use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub workflow: String,
    pub recording_run: String,
    pub source_revision: String,
    pub source_inventory: String,
    pub proof_revision: u64,
    pub engine: String,
    pub case_source: PathBuf,
}
