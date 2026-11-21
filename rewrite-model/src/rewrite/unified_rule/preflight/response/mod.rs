use crate::rewrite::*;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnvalidatedTargetWitness {
    pub case_id: String,
    pub surface: String,
    pub reason: String,
    pub source_status: u16,
    pub target_status: u16,
}
