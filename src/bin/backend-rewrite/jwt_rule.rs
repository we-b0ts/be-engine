use anyhow::{Result, ensure};
use clap::{Args, ValueEnum};
use std::path::PathBuf;
use traffic_e2e::{
    JwtRulePlanOptions,
    request_rules::{JwtAlgorithm, keys::SigningKeySource},
};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum RequestKind {
    Jwt,
}

#[derive(Debug, Args)]
pub(super) struct JwtArgs {
    /// Plan an inbound request rule instead of a response rule.
    #[arg(long, value_enum, conflicts_with = "body_codec")]
    pub request_kind: Option<RequestKind>,
    #[arg(long, requires = "request_kind")]
    rule_id: Option<String>,
    #[arg(long, requires = "request_kind")]
    header: Option<String>,
    #[arg(long, value_parser = ["HS256", "HS384", "HS512"], requires = "request_kind")]
    algorithm: Option<String>,
    #[arg(long, requires = "request_kind")]
    signing_key_ref: Option<String>,
    /// Name in the effective target startup environment; never the secret value.
    #[arg(long, conflicts_with = "target_key_file", requires = "request_kind")]
    target_env: Option<String>,
    /// Absolute container path within a captured read-only startup mount.
    #[arg(long, requires_all = ["request_kind", "target_key_field"])]
    target_key_file: Option<PathBuf>,
    #[arg(long, requires = "target_key_file")]
    target_key_field: Option<String>,
    /// Actual expiration leeway used by target validation, in seconds.
    #[arg(long, requires = "request_kind")]
    jwt_leeway_seconds: Option<i64>,
}

impl JwtArgs {
    pub(super) fn options(self) -> Result<Option<JwtRulePlanOptions>> {
        if self.request_kind.is_none() {
            return Ok(None);
        }
        let key_source = match (self.target_env, self.target_key_file, self.target_key_field) {
            (Some(name), None, None) => Some(SigningKeySource::TargetEnv { name }),
            (None, Some(path), Some(field)) => Some(SigningKeySource::TargetFile { path, field }),
            (None, None, None) => None,
            _ => anyhow::bail!("select exactly one JWT key source"),
        };
        let leeway_seconds = self.jwt_leeway_seconds.ok_or_else(|| {
            anyhow::anyhow!(
                "JWT rule requires --jwt-leeway-seconds from target validation configuration"
            )
        })?;
        ensure!(leeway_seconds >= 0, "JWT leeway must be nonnegative");
        Ok(Some(JwtRulePlanOptions {
            id: self.rule_id.unwrap_or_else(|| "session-jwt".into()),
            header: self
                .header
                .unwrap_or_else(|| "authorization".into())
                .to_ascii_lowercase(),
            algorithm: match self.algorithm.as_deref().unwrap_or("HS256") {
                "HS384" => JwtAlgorithm::HS384,
                "HS512" => JwtAlgorithm::HS512,
                _ => JwtAlgorithm::HS256,
            },
            signing_key_ref: self.signing_key_ref.unwrap_or_else(|| "session-jwt".into()),
            key_source,
            leeway_seconds,
        }))
    }
}
