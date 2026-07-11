mod config;
mod dependency_summary;
mod dns_mock;
mod http_gateway;
mod http_gateway_case;
mod http_proxy;
mod mysql_protocol;
mod mysql_proxy;
mod mysql_replay;
mod mysql_semantic;
mod process_lookup;
mod recorder;
mod recorder_event;
mod recorder_run;
mod tcp_gateway;
mod tls;
mod udp_gateway;

use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use anyhow::{Context, Result};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::{ClientConfig, RootCertStore};
use tokio::task::JoinSet;
use tracing::{info, warn};
use uuid::Uuid;

pub use config::{
    AppConfig, DnsMockConfig, HttpConfig, HttpGatewayConfig, HttpGatewayReadyConfig,
    HttpGatewayRuleConfig, MysqlConfig, MysqlRouteConfig, RecordingConfig, TcpGatewayConfig,
    TlsConfig, UdpGatewayConfig,
};
pub use dns_mock::{FakeDnsEntry, FakeDnsRegistry};
pub use mysql_replay::{
    MysqlReplayConfig, MysqlReplayControlConfig, ReplayConfig, run_mysql_replay,
    run_mysql_replay_control, run_replay,
};
pub use recorder::{
    BodyCapture, CaseBodyCapture, CaseContext, HeaderMapSnapshot, HttpExchangeEvent, MysqlColumn,
    MysqlConnectionEvent, MysqlExchangeEvent, MysqlExchangeResponse, MysqlPacketEvent,
    MysqlQueryEvent, MysqlResponseEvent, MysqlResponsePacket, MysqlTlsRejectedEvent, MysqlValue,
    ProxyErrorEvent, Recorder, RecorderEvent, TcpGatewayConnectionEvent, UdpDatagramEvent,
    capture_body, capture_body_with_original_len, capture_case_body, redact_headers,
};
pub use tls::MitmCa;

type ProxyClient = Client<HttpsConnector<HttpConnector>, http_body_util::Full<bytes::Bytes>>;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: AppConfig,
    recorder: Recorder,
    dns_registry: FakeDnsRegistry,
    ca: MitmCa,
    client: ProxyClient,
    upstream_tls_config: Arc<ClientConfig>,
    active_cases: ActiveCaseRegistry,
}

#[derive(Clone)]
struct ActiveCaseRegistry {
    state: Arc<StdMutex<ActiveCaseState>>,
}

struct ActiveCaseState {
    active: Vec<ActiveCaseRegistration>,
    bootstrap_open: bool,
    case_matching_ready: bool,
}

#[derive(Debug, Clone)]
struct ActiveCaseRegistration {
    case: CaseContext,
    upstream_pid: Option<u32>,
}

pub(crate) struct ActiveCaseGuard {
    registry: ActiveCaseRegistry,
    case_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActiveCaseRejection {
    NotReady,
    Busy,
}

impl Drop for ActiveCaseGuard {
    fn drop(&mut self) {
        self.registry.unregister(self.case_id);
    }
}

impl Default for ActiveCaseRegistry {
    fn default() -> Self {
        Self::new(true)
    }
}

impl ActiveCaseRegistry {
    fn new(case_matching_ready: bool) -> Self {
        Self {
            state: Arc::new(StdMutex::new(ActiveCaseState {
                active: Vec::new(),
                bootstrap_open: true,
                case_matching_ready,
            })),
        }
    }

    fn try_register(
        &self,
        case: CaseContext,
        upstream_pid: Option<u32>,
    ) -> Result<ActiveCaseGuard, ActiveCaseRejection> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if !state.case_matching_ready {
            return Err(ActiveCaseRejection::NotReady);
        }
        if !state.active.is_empty() {
            return Err(ActiveCaseRejection::Busy);
        }
        state.bootstrap_open = false;
        state.active.push(ActiveCaseRegistration {
            case: case.clone(),
            upstream_pid,
        });
        Ok(ActiveCaseGuard {
            registry: self.clone(),
            case_id: case.id,
        })
    }

    fn unregister(&self, case_id: Uuid) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        state
            .active
            .retain(|registration| registration.case.id != case_id);
    }

    fn close_bootstrap(&self) -> bool {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let was_open = state.bootstrap_open;
        state.bootstrap_open = false;
        state.case_matching_ready = true;
        was_open
    }

    fn is_bootstrap_open(&self) -> bool {
        let state = self.state.lock().expect("active case registry poisoned");
        state.bootstrap_open
    }

    fn current_targets_for_event(&self, event_pid: Option<u32>) -> DependencyTargets {
        let state = self.state.lock().expect("active case registry poisoned");
        let active_count = state.active.len();
        let (cases, ambiguous_active_cases) = match state.active.as_slice() {
            [] => (Vec::new(), 0),
            [registration] => {
                let matched_by = match (registration.upstream_pid, event_pid) {
                    (Some(upstream_pid), Some(event_pid)) if upstream_pid == event_pid => "process",
                    _ => "active_window",
                };
                (vec![(registration.case.clone(), matched_by)], 0)
            }
            active => (Vec::new(), active.len()),
        };
        DependencyTargets {
            bootstrap_open: state.bootstrap_open && active_count == 0,
            cases,
            ambiguous_active_cases,
        }
    }
}

struct DependencyTargets {
    cases: Vec<(CaseContext, &'static str)>,
    bootstrap_open: bool,
    ambiguous_active_cases: usize,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self> {
        let recorder = Recorder::new(&config.recording.output_dir)
            .await
            .context("failed to initialize JSONL recorder")?;
        let dns_registry = FakeDnsRegistry::load_or_new(
            &config.dns_mock.fake_cidr,
            Some(&config.dns_mock.registry_path),
            &config.dns_mock.bypass_domains,
        )
        .context("failed to initialize fake DNS registry")?;
        let ca = MitmCa::load_or_generate(&config.tls.ca_cert_path, &config.tls.ca_key_path)
            .context("failed to initialize MITM CA")?;
        let upstream_tls_config = build_upstream_tls_config(&ca)?;
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);

        let case_matching_ready = !config.http_gateway.ready.enabled;
        Ok(Self {
            inner: Arc::new(AppStateInner {
                config,
                recorder,
                dns_registry,
                ca,
                client,
                upstream_tls_config,
                active_cases: ActiveCaseRegistry::new(case_matching_ready),
            }),
        })
    }

    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    pub fn recorder(&self) -> &Recorder {
        &self.inner.recorder
    }

    pub fn dns_registry(&self) -> &FakeDnsRegistry {
        &self.inner.dns_registry
    }

    pub fn ca(&self) -> &MitmCa {
        &self.inner.ca
    }

    fn client(&self) -> &ProxyClient {
        &self.inner.client
    }

    fn upstream_tls_config(&self) -> Arc<ClientConfig> {
        self.inner.upstream_tls_config.clone()
    }

    pub(crate) fn try_register_active_case(
        &self,
        case: CaseContext,
        upstream_pid: Option<u32>,
    ) -> Result<ActiveCaseGuard, ActiveCaseRejection> {
        self.inner.active_cases.try_register(case, upstream_pid)
    }

    pub(crate) fn close_bootstrap(&self, reason: &'static str) -> bool {
        let closed = self.inner.active_cases.close_bootstrap();
        if closed {
            info!(reason, "bootstrap dependency window closed");
        }
        closed
    }

    pub(crate) fn is_bootstrap_open(&self) -> bool {
        self.inner.active_cases.is_bootstrap_open()
    }

    pub(crate) async fn record_dependency_if_relevant(&self, event: &RecorderEvent) {
        let event_pid = event_client_pid(event);
        let targets = self.inner.active_cases.current_targets_for_event(event_pid);
        if targets.bootstrap_open
            && let Err(err) = self
                .recorder()
                .append_bootstrap_dependency(event, "bootstrap_window")
                .await
        {
            warn!(
                error = %err,
                "failed to append bootstrap dependency"
            );
        }
        if targets.ambiguous_active_cases > 0 {
            warn!(
                active_cases = targets.ambiguous_active_cases,
                event_type = recorder_event_kind(event),
                "skipping case dependency because active case ownership is ambiguous"
            );
        }
        for (case, matched_by) in targets.cases {
            if let Err(err) = self
                .recorder()
                .append_case_dependency(&case, event, matched_by)
                .await
            {
                warn!(
                    error = %err,
                    case_id = %case.id,
                    rule = %case.rule_name,
                    matched_by,
                    "failed to append case dependency"
                );
            }
        }
    }

    pub async fn run(self) -> Result<()> {
        let mut tasks = JoinSet::new();

        if self.config().http.enabled {
            let http_state = self.clone();
            tasks.spawn(async move { http_proxy::run(http_state).await });
        }

        if self.config().dns_mock.enabled {
            let dns_state = self.clone();
            tasks.spawn(async move { dns_mock::run(dns_state).await });
        }

        if self.config().tcp_gateway.enabled {
            let tcp_gateway_state = self.clone();
            tasks.spawn(async move { tcp_gateway::run(tcp_gateway_state).await });
        }

        if self.config().udp_gateway.enabled {
            let udp_gateway_state = self.clone();
            tasks.spawn(async move { udp_gateway::run(udp_gateway_state).await });
        }

        if self.config().http_gateway.enabled {
            let gateway_state = self.clone();
            tasks.spawn(async move { http_gateway::run(gateway_state).await });
        }

        if self.config().mysql.enabled {
            let mysql_state = self.clone();
            tasks.spawn(async move { mysql_proxy::run(mysql_state).await });
        }

        info!(
            http_enabled = self.config().http.enabled,
            http_listen = %self.config().http.listen,
            dns_mock_enabled = self.config().dns_mock.enabled,
            tcp_gateway_enabled = self.config().tcp_gateway.enabled,
            udp_gateway_enabled = self.config().udp_gateway.enabled,
            http_gateway_enabled = self.config().http_gateway.enabled,
            mysql_enabled = self.config().mysql.enabled,
            "traffic recorder proxy started"
        );

        let run_result = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                Ok(())
            }
            Some(joined) = tasks.join_next() => {
                joined.context("proxy task panicked")?
            }
        };

        let has_failed_cases = self
            .recorder()
            .finish_run()
            .await
            .context("failed to finalize recording run")?;
        run_result?;
        if has_failed_cases {
            anyhow::bail!("recording run finished with failed cases");
        }
        Ok(())
    }
}

fn recorder_event_kind(event: &RecorderEvent) -> &'static str {
    match event {
        RecorderEvent::HttpExchange(_) => "http_exchange",
        RecorderEvent::TcpGatewayConnection(_) => "tcp_gateway_connection",
        RecorderEvent::UdpDatagram(_) => "udp_datagram",
        RecorderEvent::MysqlConnection(_) => "mysql_connection",
        RecorderEvent::MysqlQuery(_) => "mysql_query",
        RecorderEvent::MysqlResponse(_) => "mysql_response",
        RecorderEvent::MysqlExchange(_) => "mysql_exchange",
        RecorderEvent::MysqlPacket(_) => "mysql_packet",
        RecorderEvent::MysqlTlsRejected(_) => "mysql_tls_rejected",
        RecorderEvent::ProxyError(_) => "proxy_error",
    }
}

fn event_client_pid(event: &RecorderEvent) -> Option<u32> {
    match event {
        RecorderEvent::HttpExchange(event) => {
            event.client_process.as_ref().map(|process| process.pid)
        }
        RecorderEvent::TcpGatewayConnection(event) => {
            event.client_process.as_ref().map(|process| process.pid)
        }
        RecorderEvent::UdpDatagram(event) => {
            event.client_process.as_ref().map(|process| process.pid)
        }
        RecorderEvent::MysqlConnection(event) => {
            event.client_process.as_ref().map(|process| process.pid)
        }
        RecorderEvent::MysqlQuery(event) => {
            event.client_process.as_ref().map(|process| process.pid)
        }
        RecorderEvent::MysqlResponse(event) => {
            event.client_process.as_ref().map(|process| process.pid)
        }
        RecorderEvent::MysqlExchange(event) => {
            event.client_process.as_ref().map(|process| process.pid)
        }
        RecorderEvent::MysqlPacket(event) => {
            event.client_process.as_ref().map(|process| process.pid)
        }
        RecorderEvent::MysqlTlsRejected(event) => {
            event.client_process.as_ref().map(|process| process.pid)
        }
        RecorderEvent::ProxyError(event) => {
            event.client_process.as_ref().map(|process| process.pid)
        }
    }
}

fn build_upstream_tls_config(ca: &MitmCa) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
        .add(ca.ca_cert_der())
        .context("failed to add recorder CA to upstream TLS roots")?;
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_case_registry_closes_bootstrap_on_first_case() {
        let registry = ActiveCaseRegistry::default();

        let initial = registry.current_targets_for_event(None);
        assert!(initial.bootstrap_open);
        assert!(initial.cases.is_empty());

        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record-api".to_string(),
            uri_group: Some("api-user".to_string()),
        };
        let guard = registry.try_register(case.clone(), Some(42)).unwrap();

        let active = registry.current_targets_for_event(Some(42));
        assert!(!active.bootstrap_open);
        assert_eq!(active.cases, vec![(case, "process")]);

        drop(guard);
        let after_case = registry.current_targets_for_event(None);
        assert!(!after_case.bootstrap_open);
        assert!(after_case.cases.is_empty());
    }

    #[test]
    fn active_case_registry_rejects_cases_before_ready() {
        let registry = ActiveCaseRegistry::new(false);
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record-api".to_string(),
            uri_group: Some("api-user".to_string()),
        };

        assert!(matches!(
            registry.try_register(case.clone(), Some(42)),
            Err(ActiveCaseRejection::NotReady)
        ));
        assert!(registry.current_targets_for_event(None).bootstrap_open);

        assert!(registry.close_bootstrap());
        let guard = registry.try_register(case.clone(), Some(42)).unwrap();
        let active = registry.current_targets_for_event(Some(42));
        assert_eq!(active.cases, vec![(case, "process")]);
        drop(guard);
    }

    #[test]
    fn active_case_registry_allows_only_one_active_case() {
        let registry = ActiveCaseRegistry::default();
        let first = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record-api".to_string(),
            uri_group: Some("api-user".to_string()),
        };
        let second = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record-api".to_string(),
            uri_group: Some("api-user".to_string()),
        };

        let guard = registry.try_register(first, Some(42)).unwrap();
        assert!(matches!(
            registry.try_register(second.clone(), Some(43)),
            Err(ActiveCaseRejection::Busy)
        ));

        drop(guard);
        assert!(registry.try_register(second, Some(43)).is_ok());
    }

    #[test]
    fn active_case_registry_does_not_share_ambiguous_dependencies() {
        let registry = ActiveCaseRegistry::default();
        let first = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record-api".to_string(),
            uri_group: Some("api-user".to_string()),
        };
        let second = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record-api".to_string(),
            uri_group: Some("api-user".to_string()),
        };
        {
            let mut state = registry
                .state
                .lock()
                .expect("active case registry poisoned");
            state.bootstrap_open = false;
            state.active.push(ActiveCaseRegistration {
                case: first,
                upstream_pid: None,
            });
            state.active.push(ActiveCaseRegistration {
                case: second,
                upstream_pid: None,
            });
        }

        let targets = registry.current_targets_for_event(None);
        assert!(targets.cases.is_empty());
        assert_eq!(targets.ambiguous_active_cases, 2);
        assert!(!targets.bootstrap_open);
    }

    #[test]
    fn active_case_registry_can_close_bootstrap_explicitly() {
        let registry = ActiveCaseRegistry::default();

        assert!(registry.is_bootstrap_open());
        assert!(registry.close_bootstrap());
        assert!(!registry.is_bootstrap_open());
        assert!(!registry.close_bootstrap());

        let targets = registry.current_targets_for_event(None);
        assert!(!targets.bootstrap_open);
        assert!(targets.cases.is_empty());
    }
}
