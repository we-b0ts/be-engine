use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptedReview {
    pub report_path: PathBuf,
    pub context: String,
    pub receipt_identity: String,
    /// Progress of the sweep started by admission, independent of receipt age.
    pub remaining: BTreeSet<String>,
}
