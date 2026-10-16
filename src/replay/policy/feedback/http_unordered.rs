//! Evidence-gated policy authoring for HTTP dependency request array ordering.
use super::document::{render_dependency_rules, replace_dependency_rules};
use crate::replay::policy::config::{
    DependencyProtocol, HttpSelector, ReplayDependencyRule, ReplayScope, TargetSelector,
    load_replay_policy, validate_document,
};
use crate::replay::policy::http_json::{HttpJsonRules, HttpUnorderedField};
use crate::replay::{HttpUnorderedSelector, http_unordered};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::{fs, path::PathBuf};

#[derive(Debug, Clone)]
pub struct HttpUnorderedFeedback {
    pub policy_path: PathBuf,
    pub case_source: PathBuf,
    pub replay_report_path: PathBuf,
    pub rule_id: String,
    pub selector: HttpUnorderedSelector,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpUnorderedReport {
    pub policy: PathBuf,
    pub effective_rule_id: String,
    pub selector: HttpUnorderedSelector,
    pub source_evidence: String,
    pub candidates: serde_json::Value,
    pub reused_existing: bool,
    pub changed: bool,
    pub applied: bool,
    pub requires_replay: bool,
    pub diff: String,
}

pub struct HttpUnorderedPlan {
    feedback: HttpUnorderedFeedback,
    original: String,
    updated: String,
    report: HttpUnorderedReport,
}

impl HttpUnorderedPlan {
    pub fn report(&self) -> &HttpUnorderedReport {
        &self.report
    }
    pub fn apply(self) -> Result<HttpUnorderedReport> {
        ensure!(
            fs::read_to_string(&self.feedback.policy_path)? == self.original,
            "policy changed after planning; rerun HTTP unordered plan"
        );
        let current = http_unordered::evidence::verify(
            &self.feedback.case_source,
            &self.feedback.replay_report_path,
            &self.feedback.selector,
        )?;
        ensure!(
            current == self.report.candidates,
            "HTTP unordered evidence changed after planning"
        );
        if self.report.changed {
            crate::config::edit::write_atomic(&self.feedback.policy_path, self.updated.as_bytes())?;
        }
        Ok(HttpUnorderedReport {
            applied: true,
            ..self.report
        })
    }
}

pub fn plan_http_unordered(feedback: HttpUnorderedFeedback) -> Result<HttpUnorderedPlan> {
    feedback.selector.validate()?;
    crate::config::process_owned_dependencies::validate_source_evidence(&feedback.source_evidence)?;
    let original = fs::read_to_string(&feedback.policy_path)?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    let proposed = ReplayDependencyRule {
        id: feedback.rule_id.clone(),
        replay_scope: ReplayScope::Case,
        source_evidence: String::new(),
        when: None,
        case_selector: None,
        redis: None,
        protocol: DependencyProtocol::Http,
        target: TargetSelector {
            host: Some(feedback.selector.host.clone()),
            port: Some(feedback.selector.port),
        },
        http: Some(HttpSelector {
            multipart: None,
            headers: Default::default(),
            json: HttpJsonRules {
                unordered: vec![HttpUnorderedField {
                    pointer: feedback.selector.pointer.clone(),
                    source_evidence: feedback.source_evidence.clone(),
                }],
                ..Default::default()
            },
            method: feedback.selector.method.clone(),
            path: feedback.selector.path.clone(),
            query: Default::default(),
        }),
        mysql: None,
        memcached: None,
    };
    let mut document = loaded.document.clone();
    document.dependency_rules = vec![proposed.clone()];
    validate_document(&document)?;
    let candidates = http_unordered::evidence::verify(
        &feedback.case_source,
        &feedback.replay_report_path,
        &feedback.selector,
    )?;
    let existing = loaded.document.dependency_rules.iter().find(|r| {
        r.replay_scope == ReplayScope::Case
            && r.target.host == proposed.target.host
            && r.target.port == proposed.target.port
            && r.http.as_ref().is_some_and(|h| {
                h.method == feedback.selector.method
                    && h.path == feedback.selector.path
                    && h.json
                        .unordered
                        .iter()
                        .any(|f| f.pointer == feedback.selector.pointer)
            })
    });
    let reused_existing = existing.is_some();
    let effective_rule_id = existing
        .map(|r| r.id.clone())
        .unwrap_or_else(|| feedback.rule_id.clone());
    ensure!(
        loaded
            .document
            .dependency_rules
            .iter()
            .all(|r| r.id != feedback.rule_id || r.id == effective_rule_id && reused_existing),
        "HTTP unordered rule id already selects another rule"
    );
    if !reused_existing {
        loaded.document.dependency_rules.push(proposed);
    }
    validate_document(&loaded.document)?;
    let updated = replace_dependency_rules(&original, &loaded.document)?;
    let changed = original != updated;
    let diff = if changed {
        format!(
            "@@ dependency_rules @@\n{}",
            render_dependency_rules(&loaded.document)?
        )
    } else {
        String::new()
    };
    let report = HttpUnorderedReport {
        policy: feedback.policy_path.clone(),
        effective_rule_id,
        selector: feedback.selector.clone(),
        source_evidence: feedback.source_evidence.clone(),
        candidates,
        reused_existing,
        changed,
        applied: false,
        requires_replay: true,
        diff,
    };
    Ok(HttpUnorderedPlan {
        feedback,
        original,
        updated,
        report,
    })
}
