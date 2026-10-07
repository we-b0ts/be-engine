//! Canonical route selection shared by rewrite commands and regression policy.
use std::{fmt, str::FromStr};

use anyhow::{Result, ensure};

use super::RecordingApi;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordingApiScope {
    Route(String),
    Motan(RecordingApi),
}

impl FromStr for RecordingApiScope {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        if value.starts_with('/') {
            // Reuse the recording path grammar without inventing a wildcard method.
            let api = format!("GET {value}").parse::<RecordingApi>()?;
            Ok(Self::Route(api.path_pattern().into()))
        } else {
            ensure!(
                value.starts_with("MOTAN "),
                "HTTP API selectors must use a path or pattern without a method"
            );
            Ok(Self::Motan(value.parse()?))
        }
    }
}

impl fmt::Display for RecordingApiScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Route(route) => formatter.write_str(route),
            Self::Motan(api) => api.fmt(formatter),
        }
    }
}

impl From<RecordingApi> for RecordingApiScope {
    fn from(api: RecordingApi) -> Self {
        if api.method().as_str() == "MOTAN" {
            Self::Motan(api)
        } else {
            Self::Route(api.path_pattern().into())
        }
    }
}

/// Public HTTP API identity is its route; non-HTTP identities stay qualified.
pub(crate) fn identity(api: &str) -> &str {
    if api.starts_with("MOTAN ") {
        api
    } else {
        api.split_once(' ').map_or(api, |(_, path)| path)
    }
}
