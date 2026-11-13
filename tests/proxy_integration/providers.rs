use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use traffic_e2e::protocols::{
    DependencyProtocol, DependencyProvider, DependencyProviders, Probe, Recognition, Session,
    default_providers,
};
use traffic_protocol_http::{HttpConnectionSession, HttpSession};

struct CountedProvider {
    inner: Arc<dyn DependencyProvider>,
    configured: Arc<AtomicUsize>,
}

impl DependencyProvider for CountedProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn recognize(&self, probe: Probe<'_>) -> Recognition {
        self.inner.recognize(probe)
    }

    fn create_session(&self) -> Result<Session> {
        let session: HttpSession = Box::new(CountedSession {
            inner: self.inner.create_session()?.bind()?,
            configured: self.configured.clone(),
        });
        Ok(Session::new(session))
    }
}

struct CountedSession {
    inner: HttpSession,
    configured: Arc<AtomicUsize>,
}

impl HttpConnectionSession for CountedSession {
    fn configure(
        &mut self,
        builder: &mut hyper::server::conn::http1::Builder,
        preserve_header_case: bool,
    ) {
        self.configured.fetch_add(1, Ordering::Relaxed);
        self.inner.configure(builder, preserve_header_case);
    }
}

pub(super) fn counted_http_provider() -> (Arc<DependencyProviders>, Arc<AtomicUsize>) {
    let defaults = default_providers();
    let configured = Arc::new(AtomicUsize::new(0));
    let mut providers = defaults.as_ref().clone();
    providers
        .replace(
            DependencyProtocol::Http,
            Arc::new(CountedProvider {
                inner: defaults.provider(DependencyProtocol::Http).unwrap().clone(),
                configured: configured.clone(),
            }),
        )
        .unwrap();
    (Arc::new(providers), configured)
}
