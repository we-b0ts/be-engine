//! Explicit sharing of finite HTTP exchanges within one immutable recording run.
mod evidence;
pub(super) use super::identity::{recorded_fingerprint, request_fingerprint};
use super::recording;
use super::*;
use anyhow::ensure;
pub(crate) use evidence::{discover, verify_candidate};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCrossCaseSelector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub method: String,
    pub path: String,
}

impl HttpCrossCaseSelector {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.host.is_some() || self.port.is_none(),
            "HTTP shared port requires a host"
        );
        if let Some(host) = &self.host {
            let authority = host.parse::<Authority>().ok();
            ensure!(
                host.len() <= 255
                    && !host.contains('*')
                    && authority.is_some_and(
                        |authority| authority.host() == host && authority.port().is_none()
                    ),
                "HTTP shared host requires a literal host without port, path or wildcard"
            );
        }
        if let (Some(host), Some(port)) = (&self.host, self.port) {
            super::selector::HttpDependencySelector {
                host: host.clone(),
                port,
                method: self.method.clone(),
                path: self.path.clone(),
            }
            .validate()?;
        } else {
            ensure!(
                self.method.len() <= 32 && Method::from_bytes(self.method.as_bytes()).is_ok(),
                "invalid shared HTTP method"
            );
            crate::path_pattern::validate_literal_path(&self.path)?;
            ensure!(
                !self.path.contains(['?', '*']),
                "shared HTTP path cannot include a query or wildcard"
            );
        }
        Ok(())
    }

    fn matches(&self, record: &RecordedHttpExchange) -> bool {
        identity_from_record(record).is_ok_and(|identity| {
            self.host
                .as_ref()
                .is_none_or(|host| identity.target.host == super::super::normalize_host(host))
                && self.port.is_none_or(|port| identity.target.port == port)
                && record.native.method.eq_ignore_ascii_case(&self.method)
                && uri_path_only(&record.native.uri) == self.path
        })
    }

    fn covers(&self, concrete: &Self) -> bool {
        concrete
            .host
            .as_ref()
            .zip(concrete.port)
            .is_some_and(|(host, port)| {
                self.host.as_ref().is_none_or(|expected| {
                    super::super::normalize_host(expected) == super::super::normalize_host(host)
                }) && self.port.is_none_or(|expected| expected == port)
            })
            && self.method.eq_ignore_ascii_case(&concrete.method)
            && self.path == concrete.path
    }

    fn index_key(&self) -> Option<String> {
        Some(crate::dependency_index::http_key(
            self.host.as_deref()?,
            self.port?,
            &self.method,
            &self.path,
        ))
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SharedOrigin {
    pub rule_id: String,
    pub case_id: String,
    #[serde(skip)]
    pub request_fingerprint: String,
}

fn require_replayable(record: &RecordedHttpExchange) -> Result<()> {
    ensure!(
        record.native.error.is_none()
            && record
                .native
                .response_status
                .is_some_and(|s| (200..300).contains(&s)),
        "cross-case requires a successful recorded exchange"
    );
    decode_body(&record.native.request_body)?;
    decode_body(
        record
            .native
            .response_body
            .as_ref()
            .context("cross-case response body is unavailable")?,
    )?;
    Ok(())
}

/// Lazy Case loading skips only the immutable Source entries that the sharing
/// loader will install globally. A host-only declaration never invents a port.
pub(in crate::replay) fn selected_source_lines(
    path: &Path,
    index: &crate::dependency_index::FileIndex,
    reader: &mut crate::dependency_index::RecordReader,
    selectors: &[HttpCrossCaseSelector],
) -> Result<BTreeSet<usize>> {
    if selectors.is_empty() {
        return Ok(BTreeSet::new());
    }
    let keys = selectors
        .iter()
        .map(HttpCrossCaseSelector::index_key)
        .collect::<Option<BTreeSet<_>>>();
    let mut selected = BTreeSet::new();
    for entry in index
        .http
        .iter()
        .filter(|entry| keys.as_ref().is_none_or(|keys| keys.contains(&entry.key)))
    {
        let raw = reader.read(path, &index.stamp, &entry.location)?;
        let record: RecordedHttpExchange = serde_json::from_slice(&raw)?;
        if selectors.iter().any(|selector| selector.matches(&record)) {
            selected.insert(entry.location.line);
        }
    }
    Ok(selected)
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
        }
    }
    let keys = rules
        .iter()
        .map(|(_, selector)| selector.index_key())
        .collect::<Option<BTreeSet<_>>>();
    let mut reader = crate::dependency_index::RecordReader::new(16 * 1024 * 1024);
    for file in files {
        let case_id = recording::case_id(&file)?;
        if cases.contains_key(&case_id) {
            continue;
        }
        recording::visit_matching_or_all(&file, keys.as_ref(), &mut reader, |_, record| {
            let Some((rule_id, _)) = rules.iter().find(|(_, s)| s.matches(&record)) else {
                return Ok(());
            };
            require_replayable(&record)?;
            let request_fingerprint = recorded_fingerprint(&record)?;
            register_http_exchange(
                record,
                ReplaySource::Case,
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
    tracing::info!(
        source_bytes = reader.source_bytes,
        cache_hits = reader.hits,
        "loaded indexed HTTP cross-case dependencies"
    );
    // Keep ordinary inventory order; shared inventory follows capture time across APIs.
    exchanges.sort_by_key(|exchange| {
        (
            exchange.shared_origin.is_some(),
            exchange
                .shared_origin
                .as_ref()
                .and(exchange.record.native.timestamp),
        )
    });
    Ok(())
}
