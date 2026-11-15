//! Native Redis diagnostic facts and stored report extensions.
use crate::replay::report::command::{self, CommandExchangeRefReport};
use serde::Serialize;

pub(crate) type CommandMatchDiagnostic = command::CommandMatchDiagnostic<RedisDiagnostic>;
pub(crate) type CommandRequestReport = command::CommandRequestReport<RedisDiagnostic>;
pub(crate) type CommandProtocolReport =
    command::CommandProtocolReport<RedisDiagnostic, RedisReportExtensions>;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum RedisDiagnostic {
    #[serde(rename = "redis_append_stream_mismatch")]
    AppendStream {
        #[serde(flatten)]
        details: Box<crate::protocols::replay::redis::append::AppendMismatch>,
    },
    #[serde(rename = "redis_append_stream_boundary_mismatch")]
    AppendStreamBoundary {
        #[serde(flatten)]
        details: Box<crate::protocols::replay::redis::append::AppendBoundaryMismatch>,
    },
    #[serde(rename = "redis_state_observation_mismatch")]
    StateObservation {
        rule_id: String,
        source_key_fingerprint: String,
        source_epoch_mutation: Option<Box<CommandExchangeRefReport>>,
        reason: String,
    },
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct RedisReportExtensions {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) activity_refreshes: Vec<crate::protocols::replay::redis::activity::ActivityAudit>,
    pub(crate) activity_refreshes_omitted: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) state_observations:
        Vec<crate::protocols::replay::redis::observations::ObservationAudit>,
    pub(crate) state_observations_omitted: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_state_omissions:
        Vec<crate::protocols::replay::redis::observations::omissions::OmissionAudit>,
    pub(crate) allowed_state_omissions_omitted: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target_event_index_scope: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) append_streams: Vec<crate::protocols::replay::redis::append::AppendAudit>,
    pub(crate) append_streams_omitted: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_cancelled_cache_tails:
        Vec<crate::protocols::replay::redis::append::cancelled::Audit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pubsub: Option<PubSubReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unordered_value:
        Option<crate::protocols::replay::redis::value::evidence::OrderEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PubSubReport {
    pub recorded_pushes: usize,
    pub delivered_pushes: usize,
    pub recorded_rpc_callbacks: usize,
    pub delivered_rpc_callbacks: usize,
    pub failed_pushes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_diagnostics_and_report_extensions_preserve_the_stored_shape() {
        let diagnostic = CommandMatchDiagnostic::Native(RedisDiagnostic::StateObservation {
            rule_id: "read-state".into(),
            source_key_fingerprint: "key-digest".into(),
            source_epoch_mutation: None,
            reason: "state differs".into(),
        });
        assert_eq!(
            serde_json::to_value(diagnostic).unwrap(),
            json!({
                "kind": "redis_state_observation_mismatch",
                "rule_id": "read-state",
                "source_key_fingerprint": "key-digest",
                "source_epoch_mutation": null,
                "reason": "state differs",
            })
        );
        let report = serde_json::to_value(CommandProtocolReport::default()).unwrap();
        assert_eq!(report["activity_refreshes_omitted"], 0);
        assert_eq!(report["unmatched"], json!([]));
        assert!(report.get("extensions").is_none());
    }
}
