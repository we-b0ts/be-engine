//! Exact outbound HTTP endpoint selectors shared by value and scope rules.
use super::*;
use anyhow::ensure;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpDependencySelector {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
}

impl HttpDependencySelector {
    pub(crate) fn validate(&self) -> Result<()> {
        let authority = self.host.parse::<Authority>().ok();
        ensure!(
            authority.is_some_and(|a| a.host() == self.host && a.port().is_none())
                && !self.host.contains('*')
                && self.port > 0,
            "HTTP dependency rules require an exact host and nonzero port"
        );
        ensure!(
            Method::from_bytes(self.method.as_bytes()).is_ok(),
            "invalid HTTP dependency method"
        );
        let uri = self.path.parse::<Uri>().ok();
        ensure!(
            self.path.starts_with('/')
                && !self.path.contains('*')
                && uri.is_some_and(|u| u.query().is_none() && u.path() == self.path),
            "HTTP dependency rules require an exact path without a query or wildcard"
        );
        Ok(())
    }
}
