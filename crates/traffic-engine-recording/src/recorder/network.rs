use anyhow::Result;

use super::{NetworkObservations, Recorder};
use crate::recording_network::{
    RECORDING_NETWORK_FILENAME, RecordedEndpoint, RecordingNetworkManifest, normalize_host,
};

impl Recorder {
    pub async fn observe_resolved_domain(&self, domain: &str) -> Result<()> {
        let domain = normalize_host(domain)?;
        self.network_observations
            .lock()
            .await
            .resolved_domains
            .insert(domain);
        Ok(())
    }

    pub async fn observe_accessed_endpoint(&self, host: &str, port: u16) -> Result<()> {
        let endpoint = RecordedEndpoint::new(host, port)?;
        self.network_observations
            .lock()
            .await
            .accessed_endpoints
            .insert(endpoint);
        Ok(())
    }

    pub(super) async fn write_network_manifest(&self) -> Result<()> {
        let NetworkObservations {
            resolved_domains,
            accessed_endpoints,
        } = self.network_observations.lock().await.clone();
        let manifest =
            RecordingNetworkManifest::from_observations(resolved_domains, accessed_endpoints);
        super::run::write_pretty_json(&self.run_dir.join(RECORDING_NETWORK_FILENAME), &manifest)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn finalizes_resolved_domains_and_accessed_endpoints() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        recorder
            .observe_resolved_domain("BREEZE.RECORDING.")
            .await
            .unwrap();
        recorder
            .observe_accessed_endpoint("BREEZE.RECORDING.", 9301)
            .await
            .unwrap();
        recorder
            .observe_accessed_endpoint("breeze.recording", 9301)
            .await
            .unwrap();

        recorder.finish_run().await.unwrap();
        let manifest =
            RecordingNetworkManifest::load(&recorder.run_dir.join(RECORDING_NETWORK_FILENAME))
                .unwrap();
        assert_eq!(manifest.resolved_domains, ["breeze.recording"]);
        assert_eq!(manifest.accessed_endpoints.len(), 1);
        assert_eq!(manifest.accessed_endpoints[0].host, "breeze.recording");
        assert_eq!(manifest.accessed_endpoints[0].port, 9301);
    }
}
