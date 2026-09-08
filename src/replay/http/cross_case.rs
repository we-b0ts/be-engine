//! Explicit sharing of finite HTTP exchanges within one immutable recording run.
mod evidence;
mod recording;
use super::*;
use anyhow::ensure;
pub(crate) use evidence::{discover, verify_candidate};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCrossCaseSelector {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
}

impl HttpCrossCaseSelector {
    pub(crate) fn validate(&self) -> Result<()> {
        let authority = self.host.parse::<Authority>().ok();
        ensure!(
            authority.is_some_and(|a| a.host() == self.host && a.port().is_none())
                && !self.host.contains('*')
                && self.port > 0,
            "cross-case requires an exact host and nonzero port"
        );
        ensure!(
            Method::from_bytes(self.method.as_bytes()).is_ok(),
            "invalid cross-case HTTP method"
        );
        let uri = self.path.parse::<Uri>().ok();
        ensure!(
            self.path.starts_with('/')
                && !self.path.contains('*')
                && uri.is_some_and(|u| u.query().is_none() && u.path() == self.path),
            "cross-case requires an exact path without a query or wildcard"
        );
        Ok(())
    }

    fn matches(&self, record: &RecordedHttpExchange) -> bool {
        identity_from_record(record).is_ok_and(|i| {
            i.target.host == super::super::normalize_host(&self.host)
                && i.target.port == self.port
                && record.method.eq_ignore_ascii_case(&self.method)
                && uri_path_only(&record.uri) == self.path
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SharedOrigin {
    pub rule_id: String,
    pub case_id: String,
    #[serde(skip)]
    pub request_fingerprint: String,
}

/// Keep secret values out of reports. Canonical JSON matches the ordinary matcher;
/// non-JSON bodies (including forms) retain byte identity. Query multiplicity is exact.
pub(super) fn request_fingerprint(uri: &str, body: &[u8], headers: &HeaderSnapshot) -> String {
    let body = serde_json::from_slice::<Value>(body)
        .map(|value| canonical_json(&value))
        .unwrap_or_else(|_| body.to_vec());
    let significant = ["authorization", "cookie", "content-type"].map(|name| {
        let values: Vec<_> = headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .flat_map(|(_, values)| values.iter())
            .collect();
        (name, values)
    });
    let material = serde_json::to_vec(&(normalize_uri(uri, &[]), significant))
        .expect("HTTP identity is serializable");
    let mut digest = Sha256::new();
    digest.update(b"traffic-e2e-http-cross-case-v1\0");
    digest.update((material.len() as u64).to_be_bytes());
    digest.update(material);
    digest.update(body);
    format!("sha256:{:x}", digest.finalize())
}

fn canonical_json(value: &Value) -> Vec<u8> {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), ordered(v)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(values) => Value::Array(values.iter().map(ordered).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&ordered(value)).expect("JSON is serializable")
}

pub(super) fn recorded_fingerprint(record: &RecordedHttpExchange) -> Result<String> {
    Ok(request_fingerprint(
        &record.uri,
        &decode_body(&record.request_body)?,
        &record.request_headers,
    ))
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
