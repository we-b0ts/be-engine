//! Explicit sharing of finite HTTP exchanges within one immutable recording run.
mod evidence;
pub(super) use super::identity::{recorded_fingerprint, request_fingerprint};
use super::recording;
use super::*;
use anyhow::ensure;
pub(crate) use evidence::{discover, verify_candidate};
use std::path::Path;

pub use super::selector::HttpDependencySelector as HttpCrossCaseSelector;

#[derive(Debug, Clone, Serialize)]
pub(super) struct SharedOrigin {
    pub rule_id: String,
    pub case_id: String,
    #[serde(skip)]
    pub request_fingerprint: String,
}

fn require_replayable(record: &RecordedHttpExchange) -> Result<()> {
    ensure!(
        record.error.is_none()
            && record
                .response_status
                .is_some_and(|s| (200..300).contains(&s)),
        "cross-case requires a successful recorded exchange"
    );
    decode_body(&record.request_body)?;
    decode_body(
        record
            .response_body
            .as_ref()
            .context("cross-case response body is unavailable")?,
    )?;
    Ok(())
}

pub(in crate::replay) fn load(
    root: &Path,
    policy_path: Option<&Path>,
    cases: &BTreeMap<String, super::super::ReplayCase>,
    exchanges: &mut Vec<ReplayHttpExchange>,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
) -> Result<()> {
    let Some(path) = policy_path else {
        return Ok(());
    };
    let rules = super::super::policy::http_cross_case_rules(path)?;
    if rules.is_empty() {
        return Ok(());
    }
    let (_, files) = recording::files(root)?;
    // Selected exchanges already exist in memory. Change only their derived scope.
    for exchange in exchanges.iter_mut() {
        if let Some((id, _)) = rules.iter().find(|(_, s)| s.matches(&exchange.record)) {
            require_replayable(&exchange.record)?;
            exchange.shared_origin = Some(SharedOrigin {
                rule_id: id.clone(),
                case_id: exchange.case_id.clone().unwrap_or_default(),
                request_fingerprint: recorded_fingerprint(&exchange.record)?,
            });
            exchange.source = ReplaySource::Global;
        }
    }
    for file in files {
        let case_id = recording::case_id(&file)?;
        if cases.contains_key(&case_id) {
            continue;
        }
        recording::visit(&file, |_, record| {
            let Some((rule_id, _)) = rules.iter().find(|(_, s)| s.matches(&record)) else {
                return Ok(());
            };
            require_replayable(&record)?;
            let request_fingerprint = recorded_fingerprint(&record)?;
            register_http_exchange(
                record,
                ReplaySource::Global,
                Some(&case_id),
                exchanges,
                targets,
            )?;
            exchanges
                .last_mut()
                .expect("registered exchange")
                .shared_origin = Some(SharedOrigin {
                rule_id: rule_id.clone(),
                case_id: case_id.clone(),
                request_fingerprint,
            });
            Ok(())
        })?;
    }
    // Keep ordinary inventory order; shared inventory follows capture time across APIs.
    exchanges.sort_by_key(|exchange| {
        (
            exchange.shared_origin.is_some(),
            exchange
                .shared_origin
                .as_ref()
                .and(exchange.record.timestamp),
        )
    });
    Ok(())
}
