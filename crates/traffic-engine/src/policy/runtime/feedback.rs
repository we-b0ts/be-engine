//! Compatibility endpoints for retired authoring and authenticated published evidence.
mod generated_values;
mod http_cross_case;
mod memcached;
mod model;
mod mysql_time;
mod redis_cross_case;
mod response_body;
use anyhow::{Context, Result, ensure};
pub use generated_values::{
    DependencyRequestRuleFeedback, DynamicValueMysqlTimeRule, DynamicValueRedisTimeRule,
    DynamicValueRuleFeedback, GeneratedValueRulePlan, GeneratedValueRuleReport,
    RedisJsonTimeValueSelector, ResponseHeaderDateRuleFeedback, ResponseJwtRuleFeedback,
    plan_dependency_request_rule, plan_dynamic_value_mysql_time_rule,
    plan_dynamic_value_redis_time_rule, plan_dynamic_value_rule, plan_response_header_date_rule,
    plan_response_jwt_rule,
};
pub use http_cross_case::{
    HttpCrossCaseFeedback, HttpCrossCasePlan, HttpCrossCaseReport, plan_http_cross_case,
};
pub use memcached::{
    MemcachedTimestampRuleFeedback, MemcachedTimestampRulePlan, MemcachedTimestampRuleReport,
    plan_memcached_timestamp_rule,
};
pub use model::{ResponseRuleFeedback, ResponseRuleReport};
pub use mysql_time::{
    MysqlTimeRuleFeedback, MysqlTimeRulePlan, MysqlTimeRuleReport, MysqlTimeSelector,
    MysqlTimeValueSelector, plan_mysql_time_rule,
};
pub use redis_cross_case::{
    RedisCrossCaseFeedback, RedisCrossCasePlan, RedisCrossCaseReport, plan_redis_cross_case,
};
pub use response_body::{
    ResponseBodyRuleEvidence, ResponseBodyRuleEvidenceKind, ResponseBodyRuleFeedback,
    ResponseBodyRulePlan, ResponseBodyRuleReport, ResponseBodyRuleVerificationOutcome,
    plan_response_body_rule,
};
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

pub struct ResponseRulePlan {
    report: ResponseRuleReport,
    witnesses: Vec<(PathBuf, String)>,
}
impl ResponseRulePlan {
    pub fn time_evidence_witnesses(&self) -> Vec<(PathBuf, String)> {
        self.witnesses.clone()
    }
    pub fn report(&self) -> &ResponseRuleReport {
        &self.report
    }
    pub fn apply(self) -> Result<ResponseRuleReport> {
        Err(crate::policy::legacy_authoring_error())
    }
}
pub fn plan_response_rule(_feedback: ResponseRuleFeedback) -> Result<ResponseRulePlan> {
    Err(crate::policy::legacy_authoring_error())
}
pub(crate) fn replace_request_rule_section(_original: &str, _section: &str) -> Result<String> {
    Err(crate::policy::legacy_authoring_error())
}
pub(crate) fn read_published_report(path: &Path, label: &str) -> Result<Vec<u8>> {
    if crate::dependency_index::scoped::view_path(path).is_some() {
        return crate::dependency_index::scoped::read_bytes(path);
    }
    let resolved = resolve_published_report_path(path);
    read_regular_at(&resolved, path, label)
}

fn read_regular_at(resolved: &Path, reported: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(resolved)
        .with_context(|| format!("failed to inspect {label} {}", reported.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink"
    );
    fs::read(resolved).with_context(|| format!("failed to read {label} {}", reported.display()))
}

/// Resolve a report path that may carry a stale `.active` segment left over from a
/// finalized E2E attempt. Older publishes wrote assertion-detail paths anchored at the
/// focused API `.active` directory; after publish renamed that directory to `latest`,
/// the inner paths dangled. Fall back to the `latest` sibling so existing response-rule
/// evidence remains hydratable without a fresh E2E attempt.
fn resolve_published_report_path(path: &Path) -> PathBuf {
    match fs::symlink_metadata(path) {
        Ok(_) => return path.to_path_buf(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return path.to_path_buf(),
    }
    let Some(active_dir) = path
        .ancestors()
        .find(|ancestor| ancestor.file_name() == Some(OsStr::new(".active")))
    else {
        return path.to_path_buf();
    };
    let Ok(relative) = path.strip_prefix(active_dir) else {
        return path.to_path_buf();
    };
    let candidate = active_dir.with_file_name("latest").join(relative);
    if fs::symlink_metadata(&candidate).is_ok() {
        candidate
    } else {
        path.to_path_buf()
    }
}

#[cfg(test)]
use super::response::ResponseRuleKind;
#[cfg(test)]
#[path = "feedback/path_tests.rs"]
mod path_tests;
#[cfg(test)]
#[path = "feedback/tests.rs"]
mod tests;
