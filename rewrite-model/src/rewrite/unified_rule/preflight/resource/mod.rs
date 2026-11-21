use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRecord {
    pub case_source: PathBuf,
    pub snapshot: crate::dependency_index::evidence::Snapshot,
    pub inventory_path: Option<PathBuf>,
    pub case_groups: BTreeMap<String, String>,
    /// Only identities/counts are public; original payloads remain protected.
    pub affected_apis: BTreeSet<String>,
    pub executions: BTreeMap<String, Option<Vec<Artifact>>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unavailable_executions: BTreeMap<String, Artifact>,
}
