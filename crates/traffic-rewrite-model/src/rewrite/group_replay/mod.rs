use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupReplaySummary {
    pub group_id: String,
    pub recording_run_id: String,
    pub target_fingerprint: String,
    pub kind: GroupReplayKind,
    pub results: Vec<GroupReplayResult>,
    pub remaining: Vec<String>,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interruption: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupReplayKind {
    /// First observation or a pending refresh after an invalidated execution.
    Initial,
    Acceptance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupReplayResult {
    pub api: String,
    pub methods: Vec<String>,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupReplayRound {
    pub group_id: String,
    pub recording_run_id: String,
    pub target_fingerprint: String,
    pub kind: GroupReplayKind,
    pub routes: Vec<String>,
    /// Exact method admissions are frozen before the first route is executed.
    pub methods: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub results: Vec<GroupReplayResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl GroupReplayRound {
    pub fn next(&self) -> Option<&str> {
        self.routes
            .iter()
            .find(|route| !self.results.iter().any(|result| &result.api == *route))
            .map(String::as_str)
    }

    pub fn summary(&self, interruption: Option<String>) -> GroupReplaySummary {
        let remaining = self
            .routes
            .iter()
            .filter(|route| !self.results.iter().any(|result| &result.api == *route))
            .cloned()
            .collect::<Vec<_>>();
        GroupReplaySummary {
            group_id: self.group_id.clone(),
            recording_run_id: self.recording_run_id.clone(),
            target_fingerprint: self.target_fingerprint.clone(),
            kind: self.kind,
            results: self.results.clone(),
            complete: remaining.is_empty() && interruption.is_none(),
            remaining,
            interruption,
        }
    }
}
