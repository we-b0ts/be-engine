use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRecord {
    pub case_source: PathBuf,
    pub source_revision: String,
    pub recording_run_id: String,
    pub prepared_cases: BTreeMap<String, PathBuf>,
    pub replay_report: Option<PathBuf>,
    pub inventory: NativeSourceInventory,
    pub rule_ids: BTreeSet<String>,
}
