//! Legacy identity declarations bind to the installed value policy at delivery preparation.
use anyhow::{Result, ensure};
use serde_json::Value;
use traffic_contract::{
    comparison::Difference,
    identity::PreparedIdentityDelivery,
    rule::{FieldContract, IdentityFormat},
};
use traffic_policy::{PolicyRegistry, PreparedPolicy};

#[derive(Clone, Copy)]
pub struct IdentityDelivery<'a> {
    pub prefix: &'a str,
    pub format: IdentityFormat,
    pub value: &'a Value,
}
impl IdentityDelivery<'_> {
    pub fn prepare(self, policies: &PolicyRegistry) -> Result<PreparedIdentityDelivery> {
        PreparedIdentityDelivery::prepare(self.value, policy(self.prefix, self.format, policies)?)
    }
}

fn policy(
    prefix: &str,
    format: IdentityFormat,
    policies: &PolicyRegistry,
) -> Result<PreparedPolicy> {
    let definition = FieldContract::Identity {
        prefix: prefix.into(),
        format,
    }
    .registered_definition(false)
    .expect("identity declarations lower to a registered policy");
    policies.prepare_definition(&definition)
}

pub fn token(
    value: &Value,
    prefix: &str,
    format: IdentityFormat,
    pointer: &str,
    policies: &PolicyRegistry,
) -> Result<String, Difference> {
    let select = || -> Result<String> {
        let policy = policy(prefix, format, policies)?;
        ensure!(
            policy.applies(
                &serde_json::from_value(value.clone())?,
                &traffic_value::Value::Null
            )?,
            "identity representation is invalid"
        );
        value
            .as_str()
            .and_then(|value| value.strip_prefix(prefix))
            .map(str::to_owned)
            .or_else(|| {
                value
                    .as_u64()
                    .filter(|_| prefix.is_empty())
                    .map(|value| value.to_string())
            })
            .ok_or_else(|| anyhow::anyhow!("identity type or literal prefix changed"))
    };
    select().map_err(|error| Difference {
        pointer: pointer.into(),
        reason: error.to_string(),
    })
}
