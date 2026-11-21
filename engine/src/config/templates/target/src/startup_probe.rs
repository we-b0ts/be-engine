// Initialization-only HTTPS verification.
// Delete this entire file when real target implementation begins.

use std::time::Duration;

use anyhow::{Context as _, Result};
use reqwest::redirect::Policy;

const PROBE_URL: &str = "__TRAFFIC_E2E_POSITIVE_PROBE_URL__";
const PROBE_CA_PATH: &str = "/traffic-e2e/trust/replay-ca.pem";
const PROBE_ORIGIN_HEADER: &str = "__TRAFFIC_E2E_PROBE_ORIGIN_HEADER__";
const PROBE_ORIGIN: &str = "__TRAFFIC_E2E_PROBE_ORIGIN__";

pub async fn run() -> Result<()> {
    let ca = std::fs::read(PROBE_CA_PATH)
        .with_context(|| format!("failed to read initialization probe CA {PROBE_CA_PATH}"))?;
    let ca =
        reqwest::Certificate::from_pem(&ca).context("failed to parse initialization probe CA")?;
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .build()
        .context("failed to build initialization HTTPS probe client")?;
    client
        .get(PROBE_URL)
        .header(PROBE_ORIGIN_HEADER, PROBE_ORIGIN)
        .send()
        .await
        .context("initialization HTTPS probe failed")?;
    Ok(())
}
