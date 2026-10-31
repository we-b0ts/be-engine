//! Admission is actual Target I/O, never a Source claim or inferred consumption.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
mod registry;
pub(super) use registry::Admission;

#[cfg(test)]
mod tests;

const MAX_OBSERVATIONS: usize = 65_536;
const READING: u8 = 0;
const COMPLETE: u8 = 1;
const CANCELLED: u8 = 2;
const BODY_ERROR: u8 = 3;

#[derive(Debug, Default)]
struct Owners {
    cases: BTreeSet<String>,
    startup: usize,
    process: usize,
    shared: usize,
    head_sha256: String,
}

// A path index deliberately over-approximates candidates: a query/header/body
// difference cannot accidentally prove that an otherwise possible Case is Process.
type HeadKey = (String, u16, String, String, bool);

#[derive(Debug, Default)]
pub(in crate::replay) struct HttpIngress {
    heads: BTreeMap<HeadKey, Owners>,
    cases: BTreeMap<String, Arc<AtomicUsize>>,
    run: Arc<AtomicUsize>,
    registry: Arc<std::sync::Mutex<registry::Registry>>,
    pub(in crate::replay) changed: Arc<tokio::sync::Notify>,
}

#[derive(Debug, Serialize)]
pub(in crate::replay) struct IngressObservation {
    observation_id: uuid::Uuid,
    observed_case_id: Option<String>,
    request_started_at: chrono::DateTime<Utc>,
    startup_admitted: bool,
    process_head_unique: bool,
    head_sha256: String,
    status: &'static str,
}

#[derive(Debug, Serialize)]
pub(in crate::replay) struct IngressReport {
    pub observations: Vec<IngressObservation>,
    pub omitted: usize,
    pub pending: usize,
}
impl IngressReport {
    pub(in crate::replay) fn is_dirty(&self) -> bool {
        self.omitted > 0
            || self.pending > 0
            || self
                .observations
                .iter()
                .any(|o| matches!(o.status, "cancelled" | "body_error"))
    }
}

fn key(scheme: HttpReplayScheme, target: &TargetKey, method: &str, path: &str) -> HeadKey {
    (
        target.host.clone(),
        target.port,
        method.to_ascii_uppercase(),
        path.to_string(),
        scheme == HttpReplayScheme::Https,
    )
}

impl HttpIngress {
    pub(in crate::replay) fn register(&mut self, exchanges: &[ReplayHttpExchange]) {
        for exchange in exchanges {
            let owners = self
                .heads
                .entry(key(
                    exchange.identity.scheme,
                    &exchange.identity.target,
                    &exchange.record.method,
                    &uri_path_only(&exchange.record.uri),
                ))
                .or_default();
            if owners.head_sha256.is_empty() {
                owners.head_sha256 = crate::policy_evidence::digest(
                    &serde_json::to_vec(&key(
                        exchange.identity.scheme,
                        &exchange.identity.target,
                        &exchange.record.method,
                        &uri_path_only(&exchange.record.uri),
                    ))
                    .expect("HTTP head key is serializable"),
                );
            }
            owners.shared += usize::from(exchange.shared_origin.is_some());
            match exchange.source {
                ReplaySource::Case => {
                    if let Some(case) = &exchange.case_id {
                        owners.cases.insert(case.clone());
                    }
                }
                ReplaySource::Startup => owners.startup += 1,
                ReplaySource::Process => owners.process += 1,
            }
        }
    }

    pub(super) fn handle(&self) -> registry::Handle {
        registry::Handle::new(
            self.registry.clone(),
            self.run.clone(),
            self.changed.clone(),
        )
    }
    pub(in crate::replay) fn activate_case(&mut self, case: Option<&str>) {
        let count = case
            .map(|case| self.cases.entry(case.into()).or_default().clone())
            .unwrap_or_else(|| self.run.clone());
        self.registry
            .lock()
            .expect("HTTP ingress registry poisoned")
            .activate(case, count);
    }
    pub(in crate::replay) fn close_startup(&self) {
        self.registry
            .lock()
            .expect("HTTP ingress registry poisoned")
            .startup_open = false;
    }
    pub(in crate::replay) fn try_close_case(&self, case: &str) -> bool {
        self.registry
            .lock()
            .expect("HTTP ingress registry poisoned")
            .try_close(case)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn configure_head(
        &self,
        admission: &mut Admission,
        scheme: HttpReplayScheme,
        target: &TargetKey,
        method: &Method,
        uri: &Uri,
        host: Option<&str>,
    ) {
        let head = key(scheme, target, method.as_str(), uri.path());
        let owner = self.heads.get(&head);
        let process = host.is_none_or(|host| host_matches_target(host, target))
            && owner.is_some_and(|owner| {
                owner.process == 1
                    && owner.shared == 0
                    && owner.startup == 0
                    && admission
                        .case_id()
                        .is_none_or(|case| !owner.cases.contains(case))
            });
        let digest = owner
            .map(|owner| owner.head_sha256.clone())
            .unwrap_or_else(|| {
                crate::policy_evidence::digest(
                    &serde_json::to_vec(&head).expect("HTTP head key is serializable"),
                )
            });
        admission.configure_head(digest, process, &self.run);
    }
    pub(in crate::replay) fn has_case_pending(&self, case: Option<&str>) -> bool {
        case.and_then(|case| self.cases.get(case))
            .is_some_and(|count| count.load(Ordering::Acquire) > 0)
    }
    pub(in crate::replay) fn has_pending(&self) -> bool {
        self.run.load(Ordering::Acquire) > 0
            || self.cases.values().any(|n| n.load(Ordering::Acquire) > 0)
    }
    pub(in crate::replay) fn case_failed(&self, case: &str) -> bool {
        let registry = self
            .registry
            .lock()
            .expect("HTTP ingress registry poisoned");
        registry.omitted > 0
            || registry.observations.iter().any(|o| {
                o.observed_case_id.as_deref() == Some(case)
                    && !o.process_head_unique.load(Ordering::Acquire)
                    && matches!(o.status.load(Ordering::Acquire), CANCELLED | BODY_ERROR)
            })
    }
    pub(in crate::replay) fn pending_diagnostic(&self) -> Value {
        let registry = self
            .registry
            .lock()
            .expect("HTTP ingress registry poisoned");
        let pending = registry
            .observations
            .iter()
            .filter(|o| o.status.load(Ordering::Acquire) == READING);
        let count = self.run.load(Ordering::Acquire)
            + self
                .cases
                .values()
                .map(|n| n.load(Ordering::Acquire))
                .sum::<usize>();
        let references = pending
            .take(4)
            .map(|o| {
                serde_json::json!({
                    "observation_id":o.id,"observed_case_id":o.observed_case_id,
                    "startup_admitted":o.startup_open,"process_head_unique":o.process_head_unique.load(Ordering::Acquire),
                    "request_started_at":o.started_at,"reason":"actual_request_body_io",
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({"count":count,"omitted":count.saturating_sub(references.len()),"references":references})
    }
    pub(in crate::replay) fn report(&self) -> IngressReport {
        let registry = self
            .registry
            .lock()
            .expect("HTTP ingress registry poisoned");
        IngressReport {
            pending: self.run.load(Ordering::Acquire)
                + self
                    .cases
                    .values()
                    .map(|n| n.load(Ordering::Acquire))
                    .sum::<usize>(),
            omitted: registry.omitted,
            observations: registry
                .observations
                .iter()
                .map(|o| IngressObservation {
                    observation_id: o.id,
                    observed_case_id: o.observed_case_id.clone(),
                    request_started_at: o.started_at,
                    startup_admitted: o.startup_open,
                    process_head_unique: o.process_head_unique.load(Ordering::Acquire),
                    head_sha256: o.head_sha256.get().cloned().unwrap_or_default(),
                    status: match o.status.load(Ordering::Acquire) {
                        READING => "reading_body",
                        COMPLETE => "body_complete",
                        CANCELLED => "cancelled",
                        _ => "body_error",
                    },
                })
                .collect(),
        }
    }
}

impl ReplayState {
    pub(super) fn claim_http_status(
        &mut self,
        index: usize,
        status: super::super::ReplayExchangeStatus,
    ) {
        if self.http_exchanges[index].status == super::super::ReplayExchangeStatus::StartupBlocked {
            // This can only be selected by a genuine pre-boundary admission.
            // A rejected preview or failed response materialization never pays debt.
            self.startup_phase.admit_existing_http();
        }
        self.http_exchanges[index].status = status;
    }
}

impl ReplayState {
    pub(in crate::replay) fn set_active_case(&mut self, case: Option<String>) {
        self.http_ingress.activate_case(case.as_deref());
        self.active_case_id = case;
    }
}
