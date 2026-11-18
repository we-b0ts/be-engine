use super::*;
const MAX_DURATION_MS: u64 = 86_400_000;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecordedFailure {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub protocol: String,
    pub target_host: String,
    pub target_port: u16,
    pub duration_ms: u64,
    pub failure_kind: String,
    pub client_outcome: String,
}

impl RecordedFailure {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.target_host.is_empty()
                && self.target_host.len() <= 1024
                && !self.target_host.chars().any(char::is_control)
                && self.target_port > 0,
            "recorded connection failure has no bounded physical endpoint"
        );
        ensure!(
            self.duration_ms <= MAX_DURATION_MS
                && !self.failure_kind.is_empty()
                && self.failure_kind.len() <= 128
                && !self.failure_kind.chars().any(char::is_control)
                && self.client_outcome == "reset",
            "recorded connection failure has invalid transport evidence"
        );
        ensure!(
            !self.protocol.is_empty()
                && self.protocol.len() <= 1024
                && !self.protocol.chars().any(char::is_control),
            "recorded connection failure has an invalid protocol identity"
        );
        Ok(())
    }

    pub fn matches(&self, target: &ReplayTarget) -> bool {
        normalize_host(&self.target_host) == normalize_host(&target.host)
            && self.target_port == target.port
            && (self.protocol == "tcp" || self.protocol == target.protocol.id().as_str())
    }
}
