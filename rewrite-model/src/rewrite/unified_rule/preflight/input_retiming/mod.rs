use crate::rewrite::*;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnvalidatedWitness {
    pub case_id: String,
    pub surface: String,
    pub witness_id: Option<String>,
    pub target_observation_id: Option<String>,
    pub reason: String,
}
