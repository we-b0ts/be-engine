use std::time::Duration;

use clap::ValueEnum;
use serde::Serialize;

pub(crate) const IMAGE: &str = "registry.api.demo.test/weibo_rd_if/traffic-e2e-network-probe:0.0.1@sha256:6804ffe944eb4709c4f8387e984dfcf524be14241c571756a6b6b85a8cb13f8e";
pub(crate) const POSITIVE_URL: &str = "https://demo.test/";
pub(crate) const POSITIVE_AUTHORITY: &str = "demo.test";
pub(crate) const NEGATIVE_URL: &str = "https://example.com/";
pub(crate) const NEGATIVE_AUTHORITY: &str = "example.com";
pub(crate) const SYSTEM_USER_AGENT: &str = "traffic-e2e-system-network-preflight";
pub(crate) const JAVA_USER_AGENT: &str = "traffic-e2e-java-truststore-preflight";
pub(crate) const ORIGIN_HEADER: &str = "x-traffic-e2e-probe-origin";
pub(crate) const SOURCE_ORIGIN: &str = "source";
pub(crate) const TARGET_ORIGIN: &str = "target";
pub(crate) const CASE_LIMIT_SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum PreflightProbeKind {
    JavaTruststore,
    SystemNetwork,
}

impl PreflightProbeKind {
    pub(crate) fn user_agent(self) -> &'static str {
        match self {
            Self::JavaTruststore => JAVA_USER_AGENT,
            Self::SystemNetwork => SYSTEM_USER_AGENT,
        }
    }

    pub(crate) fn matched_by(self) -> &'static str {
        match self {
            Self::JavaTruststore => "java_truststore",
            Self::SystemNetwork => "system_network",
        }
    }

    pub(crate) fn classify_recording_event(self, event: &crate::RecorderEvent) -> Option<bool> {
        let crate::RecorderEvent::HttpExchange(exchange) = event else {
            return None;
        };
        let authority_matches = exchange.authority.as_deref().is_some_and(|authority| {
            authority
                .strip_suffix(":443")
                .unwrap_or(authority)
                .eq_ignore_ascii_case(POSITIVE_AUTHORITY)
        });
        let user_agent_matches = exchange.request_headers.iter().any(|(name, values)| {
            name.eq_ignore_ascii_case("user-agent")
                && values.iter().any(|value| value == self.user_agent())
        });
        let source_origin_matches = exchange.request_headers.iter().any(|(name, values)| {
            name.eq_ignore_ascii_case(ORIGIN_HEADER)
                && values.iter().any(|value| value == SOURCE_ORIGIN)
        });
        let uri_matches = exchange.uri == "/"
            || exchange.uri == POSITIVE_URL
            || exchange.uri == "https://demo.test";
        let is_probe = exchange.method == "GET"
            && matches!(exchange.scheme.as_str(), "https" | "fake_ip_https")
            && authority_matches
            && uri_matches
            && user_agent_matches
            && source_origin_matches;
        is_probe.then(|| {
            exchange
                .response_status
                .is_some_and(|status| (100..=599).contains(&status))
                && exchange.error.is_none()
        })
    }
}
