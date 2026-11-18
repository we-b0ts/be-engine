//! Historical cross-case plan DTOs retain the unified-authoring boundary.
use crate::HttpCrossCaseSelector;
use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;
#[derive(Debug, Clone)]
pub struct HttpCrossCaseFeedback {
    pub policy_path: PathBuf,
    pub case_source: PathBuf,
    pub replay_report_path: PathBuf,
    pub rule_id: String,
    pub selector: HttpCrossCaseSelector,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpCrossCaseReport {
    pub policy: PathBuf,
    pub effective_rule_id: String,
    pub selector: HttpCrossCaseSelector,
    pub source_evidence: String,
    pub candidates: serde_json::Value,
    pub reused_existing: bool,
    pub changed: bool,
    pub applied: bool,
    pub requires_replay: bool,
    pub diff: String,
}

pub struct HttpCrossCasePlan {
    report: HttpCrossCaseReport,
}

impl HttpCrossCasePlan {
    pub fn report(&self) -> &HttpCrossCaseReport {
        &self.report
    }
    pub fn apply(self) -> Result<HttpCrossCaseReport> {
        Err(crate::policy::legacy_authoring_error())
    }
}

pub fn plan_http_cross_case(_feedback: HttpCrossCaseFeedback) -> Result<HttpCrossCasePlan> {
    Err(crate::policy::legacy_authoring_error())
}
