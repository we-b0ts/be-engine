//! Identity format comparison delegates candidate-local correspondence to the host.
use anyhow::{Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use traffic_contract::{identity, rule::IdentityFormat};
mod formats;
use traffic_policy::{
    ComparisonPolicy, Evaluation, EvaluationHost, PolicyAction, PolicyDescriptor, PolicyProvider,
    ValuePair,
};
use traffic_value::Value;

pub struct IdentityPolicy;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    #[serde(default)]
    prefix: String,
    format: IdentityFormat,
}

impl PolicyProvider for IdentityPolicy {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "identity",
            version: 1,
            description: "Validate complete identity values while preserving shared equality and injectivity",
            actions: &[PolicyAction::Compare],
        }
    }
    fn prepare(&self, options: &Value) -> Result<Arc<dyn ComparisonPolicy>> {
        let config: Configuration = serde_json::from_value(serde_json::to_value(options)?)?;
        ensure!(
            config.prefix.len() <= 256 && !config.prefix.chars().any(char::is_control),
            "identity prefix requires a bounded literal"
        );
        match config.format {
            IdentityFormat::Hex(length)
            | IdentityFormat::BoundedString(length)
            | IdentityFormat::Base64Url(length) => {
                ensure!(
                    (1..=1024).contains(&length),
                    "identity representation requires a length in 1..1024"
                );
            }
            _ => {}
        }
        Ok(Arc::new(config))
    }
}

impl ComparisonPolicy for Configuration {
    fn validate_schema(&self, schema: &traffic_value::schema::FieldSchema) -> Result<()> {
        ensure!(
            matches!(
                schema,
                traffic_value::schema::FieldSchema::Dynamic
                    | traffic_value::schema::FieldSchema::Scalar
            ),
            "identity contracts require JSON or a physical SQL scalar"
        );
        Ok(())
    }

    fn applies(&self, source: &Value, _: &Value) -> Result<bool> {
        Ok(formats::token(
            &serde_json::to_value(source)?,
            &self.prefix,
            self.format,
            "",
        )
        .is_ok())
    }
    fn entity_key(&self, source: &Value) -> Result<Option<[u8; 32]>> {
        let source = serde_json::to_value(source)?;
        formats::token(&source, &self.prefix, self.format, "")
            .map_err(|error| anyhow::anyhow!(error.reason))?;
        let key = identity::key(&source, "").map_err(|error| anyhow::anyhow!(error.reason))?;
        Ok(Some(Sha256::digest(key.as_bytes()).into()))
    }
    fn evaluate(&self, pair: &ValuePair<'_>, host: &mut dyn EvaluationHost) -> Result<Evaluation> {
        if pair.source != pair.target {
            let source = serde_json::to_value(pair.source)?;
            let target = serde_json::to_value(pair.target)?;
            if source.is_string() != target.is_string() || source.is_number() != target.is_number()
            {
                return Ok(Evaluation::mismatch(
                    pair,
                    "identity_type",
                    "identity scalar representation changed",
                ));
            }
            for value in [&source, &target] {
                if let Err(error) = formats::token(value, &self.prefix, self.format, "") {
                    return Ok(Evaluation::mismatch(pair, "identity_format", &error.reason));
                }
            }
        }
        host.relate(pair)?;
        Ok(Evaluation::matched())
    }
}
