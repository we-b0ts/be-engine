//! Source-proven, stale-safe authoring for dependency HTTP header timestamps.
use super::document::{render_dependency_rules, replace_dependency_rules};
use crate::replay::http::request_headers::timestamp_evidence;
use crate::replay::policy::{HttpHeaderTimestampSelector, config::*, http_headers::HttpHeaderRule};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::{fs, path::PathBuf};

#[derive(Debug, Clone)]
pub struct HttpHeaderTimestampFeedback {
    pub policy_path: PathBuf,
    pub case_source: PathBuf,
    pub replay_report_path: PathBuf,
    pub rule_id: String,
    pub selector: HttpHeaderTimestampSelector,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpHeaderTimestampReport {
    pub policy: PathBuf,
    pub effective_rule_id: String,
    pub selector: HttpHeaderTimestampSelector,
    pub source_evidence: String,
    pub candidates: serde_json::Value,
    pub reused_existing: bool,
    pub changed: bool,
    pub applied: bool,
    pub requires_replay: bool,
    pub diff: String,
}

pub struct HttpHeaderTimestampPlan {
    feedback: HttpHeaderTimestampFeedback,
    original: String,
    updated: String,
    report: HttpHeaderTimestampReport,
}

impl HttpHeaderTimestampPlan {
    pub fn report(&self) -> &HttpHeaderTimestampReport {
        &self.report
    }
    pub fn apply(self) -> Result<HttpHeaderTimestampReport> {
        crate::policy::retired_authoring()?;
        ensure!(
            fs::read_to_string(&self.feedback.policy_path)? == self.original,
            "policy changed after planning; rerun HTTP header timestamp plan"
        );
        ensure!(
            timestamp_evidence::verify(
                &self.feedback.case_source,
                &self.feedback.replay_report_path,
                &self.feedback.selector
            )? == self.report.candidates,
            "HTTP header timestamp evidence changed after planning"
        );
        if self.report.changed {
            crate::config::edit::write_atomic(&self.feedback.policy_path, self.updated.as_bytes())?;
        }
        Ok(HttpHeaderTimestampReport {
            applied: true,
            ..self.report
        })
    }
}

pub fn plan_http_header_timestamp(
    mut feedback: HttpHeaderTimestampFeedback,
) -> Result<HttpHeaderTimestampPlan> {
    crate::policy::retired_authoring()?;
    feedback.selector.header = feedback.selector.header.to_ascii_lowercase();
    feedback.selector.host = feedback.selector.host.to_ascii_lowercase();
    feedback.selector.method = feedback.selector.method.to_ascii_uppercase();
    feedback.selector.validate()?;
    crate::config::process_owned_dependencies::validate_source_evidence(&feedback.source_evidence)?;
    let original = fs::read_to_string(&feedback.policy_path)?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    let candidates = timestamp_evidence::verify(
        &feedback.case_source,
        &feedback.replay_report_path,
        &feedback.selector,
    )?;
    let existing = loaded.document.dependency_rules.iter().find(|rule| {
        rule.target
            .host
            .as_ref()
            .is_some_and(|h| h.eq_ignore_ascii_case(&feedback.selector.host))
            && rule.target.port == Some(feedback.selector.port)
            && rule.http.as_ref().is_some_and(|http| {
                http.method.eq_ignore_ascii_case(&feedback.selector.method)
                    && http.path == feedback.selector.path
                    && http.headers.iter().any(|(name, field)| {
                        name.eq_ignore_ascii_case(&feedback.selector.header)
                            && field.format() == feedback.selector.format
                    })
            })
    });
    let reused_existing = existing.is_some();
    let effective_rule_id = existing
        .map(|rule| rule.id.clone())
        .unwrap_or_else(|| feedback.rule_id.clone());
    ensure!(
        loaded.document.dependency_rules.iter().all(|rule| {
            rule.id != feedback.rule_id || (reused_existing && rule.id == effective_rule_id)
        }),
        "HTTP header timestamp rule id already selects another rule"
    );
    if !reused_existing {
        loaded.document.dependency_rules.push(ReplayDependencyRule {
            id: feedback.rule_id.clone(),
            replay_scope: ReplayScope::Case,
            source_evidence: String::new(),
            when: None,
            case_selector: None,
            protocol: DependencyProtocol::Http,
            target: TargetSelector {
                host: Some(feedback.selector.host.clone()),
                port: Some(feedback.selector.port),
            },
            mysql: None,
            memcached: None,
            redis: None,
            http: Some(HttpSelector {
                multipart: None,
                method: feedback.selector.method.clone(),
                path: feedback.selector.path.clone(),
                query: Default::default(),
                json: Default::default(),
                headers: [(
                    feedback.selector.header.clone(),
                    HttpHeaderRule::Timestamp {
                        format: feedback.selector.format,
                        source_evidence: feedback.source_evidence.clone(),
                    },
                )]
                .into(),
            }),
        });
    }
    validate_document(&loaded.document)?;
    let updated = replace_dependency_rules(&original, &loaded.document)?;
    let changed = original != updated;
    let report = HttpHeaderTimestampReport {
        policy: feedback.policy_path.clone(),
        effective_rule_id,
        selector: feedback.selector.clone(),
        source_evidence: feedback.source_evidence.clone(),
        candidates,
        reused_existing,
        changed,
        applied: false,
        requires_replay: true,
        diff: if changed {
            format!(
                "@@ dependency_rules @@\n{}",
                render_dependency_rules(&loaded.document)?
            )
        } else {
            String::new()
        },
    };
    Ok(HttpHeaderTimestampPlan {
        feedback,
        original,
        updated,
        report,
    })
}
