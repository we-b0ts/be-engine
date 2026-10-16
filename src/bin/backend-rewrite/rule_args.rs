//! One self-contained rule document for every policy effect.
use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub(super) struct RulePlanArgs {
    /// One rule, a rule list, or a traffic-policy/v1 document with inline Source proof.
    #[arg(long, visible_alias = "rules", value_name = "RULES_YAML")]
    pub(super) file: PathBuf,
    /// Coordinator-issued evidence for the active issue and actual attempt.
    #[arg(long = "evidence", visible_alias = "evidence-id")]
    pub(super) evidence_id: String,
}
