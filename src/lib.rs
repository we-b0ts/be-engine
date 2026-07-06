mod config;
mod dns_mock;
mod http_gateway;
mod http_proxy;
mod mysql_protocol;
mod mysql_proxy;
mod mysql_semantic;
mod process_lookup;
mod recorder;
mod tcp_gateway;
mod tls;

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
    AppConfig, DnsMockConfig, HttpConfig, HttpGatewayConfig, HttpGatewayRuleConfig, MysqlConfig,
    MysqlRouteConfig, RecordingConfig, TcpGatewayConfig, TlsConfig,
};
pub use dns_mock::{FakeDnsEntry, FakeDnsRegistry};
pub use recorder::{
    BodyCapture, CaseBodyCapture, CaseContext, HeaderMapSnapshot, HttpExchangeEvent, MysqlColumn,
    MysqlConnectionEvent, MysqlExchangeEvent, MysqlExchangeResponse, MysqlPacketEvent,
    MysqlQueryEvent, MysqlResponseEvent, MysqlResponsePacket, MysqlTlsRejectedEvent, MysqlValue,
    ProxyErrorEvent, Recorder, RecorderEvent, TcpGatewayConnectionEvent, capture_body,
    capture_body_with_original_len, capture_case_body, redact_headers,
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

#[derive(Clone, Default)]
struct ActiveCaseRegistry {
    active: Arc<StdMutex<Vec<ActiveCaseRegistration>>>,
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

impl Drop for ActiveCaseGuard {
    fn drop(&mut self) {
        self.registry.unregister(self.case_id);
    }
}

impl ActiveCaseRegistry {
    fn register(&self, case: CaseContext, upstream_pid: Option<u32>) -> ActiveCaseGuard {
        let mut active = self.active.lock().expect("active case registry poisoned");
        active.push(ActiveCaseRegistration {
            case: case.clone(),
            upstream_pid,
        });
        ActiveCaseGuard {
            registry: self.clone(),
            case_id: case.id,
        }
    }

    fn unregister(&self, case_id: Uuid) {
        let mut active = self.active.lock().expect("active case registry poisoned");
        active.retain(|registration| registration.case.id != case_id);
    }

    fn current_dependencies_for_event(
        &self,
        event_pid: Option<u32>,
    ) -> Vec<(CaseContext, &'static str)> {
        let active = self.active.lock().expect("active case registry poisoned");
        active
            .iter()
            .map(|registration| {
                let matched_by = match (registration.upstream_pid, event_pid) {
                    (Some(upstream_pid), Some(event_pid)) if upstream_pid == event_pid => "process",
                    _ => "active_window",
                };
                (registration.case.clone(), matched_by)
            })
            .collect()
    }
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

        Ok(Self {
            inner: Arc::new(AppStateInner {
                config,
                recorder,
                dns_registry,
                ca,
                client,
                upstream_tls_config,
                active_cases: ActiveCaseRegistry::default(),
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

    pub(crate) fn register_active_case(
        &self,
        case: CaseContext,
        upstream_pid: Option<u32>,
    ) -> ActiveCaseGuard {
        self.inner.active_cases.register(case, upstream_pid)
    }

    pub(crate) async fn record_case_dependency_if_active(&self, event: &RecorderEvent) {
        let event_pid = event_client_pid(event);
        let dependencies = self
            .inner
            .active_cases
            .current_dependencies_for_event(event_pid);
        for (case, matched_by) in dependencies {
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
            http_gateway_enabled = self.config().http_gateway.enabled,
            mysql_enabled = self.config().mysql.enabled,
            "traffic recorder proxy started"
        );

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                Ok(())
            }
            Some(joined) = tasks.join_next() => {
                joined.context("proxy task panicked")?
            }
        }
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
