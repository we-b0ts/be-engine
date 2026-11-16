use super::*;
use crate::protocols::{DependencyProtocol, DependencyProviders};
use serde_json::json;
use std::sync::Arc;
use traffic_protocol::evidence::EvidenceAdapter;
use traffic_protocol::{DependencyProvider, Probe, Recognition, Session};

struct RestoredProvider;
impl DependencyProvider for RestoredProvider {
    fn name(&self) -> &'static str {
        "memcached"
    }
    fn recognize(&self, _probe: Probe<'_>) -> Recognition {
        Recognition::Reject
    }
    fn create_session(&self) -> Result<Session> {
        traffic_protocol_fixture::Provider.create_session()
    }
    fn evidence(&self) -> Option<Arc<dyn EvidenceAdapter>> {
        Some(Arc::new(RestoredEvidence))
    }
}

struct RestoredEvidence;
impl EvidenceAdapter for RestoredEvidence {
    fn schema(&self) -> &'static str {
        "test-restored-provider/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["memcached_connection", "memcached_exchange"]
    }
    fn supports_replay(&self, _event: &Value) -> bool {
        true
    }
}

#[test]
fn retired_native_evidence_requires_its_actual_provider() {
    let providers = crate::protocols::default_providers();
    for kind in [
        "memcached_connection",
        "memcached_exchange",
        "motan_connection",
        "motan_exchange",
        "kafka_connection",
        "kafka_produce",
        "kafka_fetch",
        "kafka_delivery",
    ] {
        let event = json!({"event_type":kind});
        let parsed: DependencyRecord = serde_json::from_value(event.clone()).unwrap();
        assert!(matches!(parsed, DependencyRecord::Native(_)));
        let error = validate_installed_provider(&event, &providers).unwrap_err();
        assert!(error.to_string().contains(kind), "{error}");
        assert!(error.to_string().contains("installed"), "{error}");
    }
}

#[test]
fn installing_a_provider_reuses_the_open_native_record_path() {
    let mut providers = (*crate::protocols::default_providers()).clone();
    providers
        .register(
            DependencyProtocol::new("memcached"),
            Arc::new(RestoredProvider),
        )
        .unwrap();
    for kind in ["memcached_connection", "memcached_exchange"] {
        let event = json!({"event_type":kind});
        validate_installed_provider(&event, &providers).unwrap();
        assert!(providers.event_provider(&event).is_some());
    }
    assert!(
        validate_installed_provider(
            &json!({"event_type":"memcached_exchange"}),
            &DependencyProviders::default(),
        )
        .is_err()
    );
}

#[test]
fn retired_capture_errors_cannot_leave_an_empty_replay_inventory() {
    for protocol in ["memcached", "motan", "kafka"] {
        let event = RecordedProxyError {
            protocol: protocol.into(),
            error: "capture interrupted".into(),
        };
        let error = reject_retired_proxy_error(&event).unwrap_err();
        assert!(error.to_string().contains(protocol), "{error}");
    }
}
