use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReplayDependencyLoading {
    pub lazy_cases: bool,
    pub cache_bytes: usize,
    pub index_timeout_seconds: u64,
    pub case_timeout_seconds: u64,
}

impl Default for ReplayDependencyLoading {
    fn default() -> Self {
        Self {
            lazy_cases: false,
            cache_bytes: 256 * 1024 * 1024,
            index_timeout_seconds: 1800,
            case_timeout_seconds: 180,
        }
    }
}

impl ReplayDependencyLoading {
    pub(crate) fn managed_default() -> Self {
        Self {
            lazy_cases: true,
            ..Self::default()
        }
    }
    pub(crate) fn deserialize_managed<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let supplied = serde_json::Value::deserialize(deserializer)?;
        let mut defaults =
            serde_json::to_value(Self::managed_default()).map_err(serde::de::Error::custom)?;
        let values = supplied
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("dependency_loading must be a mapping"))?;
        defaults
            .as_object_mut()
            .expect("loading config object")
            .extend(values.clone());
        serde_json::from_value(defaults).map_err(serde::de::Error::custom)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.index_timeout_seconds > 0 && self.case_timeout_seconds > 0,
            "dependency preparation timeouts must be positive"
        );
        ensure!(
            self.cache_bytes <= 4 * 1024 * 1024 * 1024usize,
            "dependency cache must not exceed 4 GiB"
        );
        Ok(())
    }
}
