//! Compact command arguments lower to the existing atomic sequence owner.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::native::{Proven, ScriptIdentity, SequenceArgument, SequenceCommand};
use crate::{
    ClockScope, GlobalField, GlobalTimeFormat, Proof, TimeAnchor, TimeContract, TimeRelation,
    TimestampFormat,
};

pub const AUTO_GROUP: &str = "auto-redis-argument-";

#[derive(Debug, Clone, PartialEq)]
pub struct Commands(Vec<Command>);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Command {
    Operation(String),
    Detailed(Details),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Details {
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<ScriptIdentity>,
    #[serde(
        default,
        deserialize_with = "crate::strict_map::unique_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub arguments: BTreeMap<usize, GlobalField>,
}

impl<'de> Deserialize<'de> for Commands {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Self(Vec::<Command>::deserialize(deserializer)?);
        value.lower(None).map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl Serialize for Commands {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl Commands {
    pub fn compile(
        &self,
        proof: Option<&Proof>,
        context: &crate::AuthoringContext<'_>,
    ) -> Result<Vec<SequenceCommand>> {
        for command in &self.0 {
            if let Command::Detailed(command) = command {
                for field in command.arguments.values() {
                    field.validate_with_registry(context.compilation.policies)?;
                }
            }
        }
        self.lower(proof)
    }

    pub fn lower(&self, proof: Option<&Proof>) -> Result<Vec<SequenceCommand>> {
        ensure!(
            (1..=16).contains(&self.0.len()),
            "Redis commands requires 1..16 operations"
        );
        let mut operations = BTreeSet::new();
        let mut commands = Vec::with_capacity(self.0.len());
        for command in &self.0 {
            let (operation, script, arguments) = match command {
                Command::Operation(operation) => (operation.as_str(), None, None),
                Command::Detailed(command) => (
                    command.operation.as_str(),
                    command.script.as_ref(),
                    Some(&command.arguments),
                ),
            };
            let operation = operation.to_ascii_uppercase();
            ensure!(
                !operation.is_empty()
                    && operation.len() <= 32
                    && operation.bytes().all(|byte| byte.is_ascii_uppercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'.')),
                "Redis command requires a bounded operation name"
            );
            ensure!(
                operations.insert(operation.clone()),
                "duplicate Redis command operation"
            );
            script_identity(&operation, script)?;
            let mut lowered = BTreeMap::new();
            if let Some(arguments) = arguments {
                ensure!(
                    arguments.len() <= 32,
                    "Redis command exceeds 32 argument declarations"
                );
                for (&index, field) in arguments {
                    ensure!(
                        (1..=128).contains(&index),
                        "Redis argument index requires 1..128; declare key formats separately"
                    );
                    let GlobalField::Time { formats } = field else {
                        anyhow::bail!(
                            "Redis arguments accept only scalar time formats; JSON fields belong in root json.fields"
                        );
                    };
                    ensure!(
                        formats.len() == 1,
                        "Redis scalar time argument requires exactly one format"
                    );
                    let format = &formats[0];
                    ensure!(
                        format.format != TimestampFormat::CalendarDate,
                        "calendar_date requires a decoded value contract"
                    );
                    let time = TimeContract {
                        format: format.format,
                        relation: TimeRelation::PreserveOffset,
                        anchor: TimeAnchor::Observation,
                        utc_offset: format.utc_offset.clone(),
                        clock_group: Some(format!("{AUTO_GROUP}{index}")),
                        clock_scope: ClockScope::default(),
                    };
                    traffic_policy_compiler::native_compile::time::validate_time(&time)?;
                    lowered.insert(
                        index,
                        Proven {
                            contract: SequenceArgument::Time(time),
                            proof: proof.cloned(),
                        },
                    );
                }
            }
            commands.push(SequenceCommand {
                operation,
                script: script.cloned().map(|contract| Proven {
                    contract,
                    proof: proof.cloned(),
                }),
                arguments: lowered,
            });
        }
        Ok(commands)
    }

    /// Fold only the canonical generated spelling, leaving additional native
    /// constraints and explicit clock relationships with their original owner.
    pub fn reverse(commands: &[SequenceCommand]) -> Result<Option<Self>> {
        let mut compact = Vec::with_capacity(commands.len());
        let mut semantic = commands.to_vec();
        for (command, semantic) in commands.iter().zip(&mut semantic) {
            let mut arguments = BTreeMap::new();
            for (&index, argument) in &command.arguments {
                let SequenceArgument::Time(time) = &argument.contract else {
                    return Ok(None);
                };
                arguments.insert(
                    index,
                    GlobalField::Time {
                        formats: vec![GlobalTimeFormat {
                            format: time.format,
                            utc_offset: time.utc_offset.clone(),
                        }],
                    },
                );
            }
            let script = command.script.as_ref().map(|value| value.contract.clone());
            compact.push(if script.is_none() && arguments.is_empty() {
                Command::Operation(command.operation.clone())
            } else {
                Command::Detailed(Details {
                    operation: command.operation.clone(),
                    script,
                    arguments,
                })
            });
            if let Some(script) = &mut semantic.script {
                script.proof = None;
            }
            for argument in semantic.arguments.values_mut() {
                argument.proof = None;
            }
        }
        let compact = Self(compact);
        let Ok(canonical) = compact.lower(None) else {
            return Ok(None);
        };
        Ok((canonical == semantic).then_some(compact))
    }
}

pub fn script_identity(operation: &str, script: Option<&ScriptIdentity>) -> Result<()> {
    let Some(script) = script else {
        ensure!(
            !matches!(operation, "EVAL" | "EVALSHA"),
            "Redis script command requires its exact script identity"
        );
        return Ok(());
    };
    let (hash, size) = match operation {
        "EVALSHA" if script.sha256.is_none() => (script.sha1.as_deref(), 40),
        "EVAL" if script.sha1.is_none() => (script.sha256.as_deref(), 64),
        _ => anyhow::bail!("Redis script identity requires sha1 for EVALSHA or sha256 for EVAL"),
    };
    ensure!(
        hash.is_some_and(|hash| hash.len() == size
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())),
        "Redis script identity requires its bounded lowercase hexadecimal digest"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ordered_operations_and_scalar_formats_roundtrip_without_authored_clocks() {
        let value = json!(["INCRBY",{"operation":"EXPIRE","arguments":{"1":{"kind":"time","formats":["unix_seconds"]}}}]);
        let commands: Commands = serde_yaml::from_str(&value.to_string()).unwrap();
        let native = commands.lower(None).unwrap();
        let yaml:Commands=serde_yaml::from_str("- INCRBY\n- operation: EXPIRE\n  arguments:\n    1: {kind: time, formats: [unix_seconds]}\n").unwrap();
        assert_eq!(yaml.lower(None).unwrap(), native);
        assert_eq!(
            native
                .iter()
                .map(|command| command.operation.as_str())
                .collect::<Vec<_>>(),
            vec!["INCRBY", "EXPIRE"]
        );
        let SequenceArgument::Time(time) = &native[1].arguments[&1].contract else {
            panic!("time argument");
        };
        assert_eq!(time.clock_group.as_deref(), Some("auto-redis-argument-1"));
        let rendered = serde_json::to_value(Commands::reverse(&native).unwrap().unwrap()).unwrap();
        assert_eq!(rendered, value);
        for forbidden in ["clock_group", "relation", "anchor", "fields", "proof"] {
            assert!(!rendered.to_string().contains(forbidden));
        }
    }

    #[test]
    fn exact_script_digest_and_actual_proof_are_retained_only_in_native_plan() {
        let value = json!([{"operation":"EVALSHA","script":{"sha1":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "arguments":{"3":{"kind":"time","formats":["unix_microseconds"]}}}]);
        let commands: Commands = serde_yaml::from_str(&value.to_string()).unwrap();
        let proof: Proof = serde_yaml::from_str(
            "source: metrics.py:42\nfact: Source script writes one generated timestamp\n",
        )
        .unwrap();
        let native = commands.lower(Some(&proof)).unwrap();
        assert_eq!(
            native[0].script.as_ref().unwrap().contract.sha1.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            native[0].script.as_ref().unwrap().proof.as_ref(),
            Some(&proof)
        );
        assert_eq!(native[0].arguments[&3].proof.as_ref(), Some(&proof));
        assert_eq!(
            serde_json::to_value(Commands::reverse(&native).unwrap().unwrap()).unwrap(),
            value
        );
        let mut explicit = native.clone();
        let SequenceArgument::Time(time) = &mut explicit[0].arguments.get_mut(&3).unwrap().contract
        else {
            unreachable!();
        };
        time.clock_group = Some("business-clock".into());
        assert!(Commands::reverse(&explicit).unwrap().is_none());
    }

    #[test]
    fn malformed_permissions_and_authored_clock_relations_are_rejected() {
        for value in [
            json!([]),
            json!(["SET", "set"]),
            json!(["EVALSHA"]),
            json!([{"operation":"SET","unknown":true}]),
            json!([{"operation":"SET","arguments":{"0":{"kind":"time","formats":["unix_seconds"]}}}]),
            json!([{"operation":"SET","arguments":{"1":{"kind":"time","formats":["unix_seconds","unix_milliseconds"]}}}]),
            json!([{"operation":"SET","arguments":{"1":{"kind":"identity","formats":["uuid"]}}}]),
            json!([{"operation":"SET","arguments":{"1":{"kind":"json","fields":{}}}}]),
            json!([{"operation":"SET","arguments":{"1":{"kind":"time","formats":["unix_seconds"],"clock_group":"authored"}}}]),
            json!([{"operation":"SET","arguments":{"1":{"kind":"time","formats":["unix_seconds"],"relation":"request_window"}}}]),
            json!([{"operation":"EVALSHA","script":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]),
            json!([{"operation":"SET","script":{"sha1":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]),
        ] {
            assert!(
                serde_yaml::from_str::<Commands>(&value.to_string()).is_err(),
                "accepted {value}"
            );
        }
        assert!(serde_yaml::from_str::<Commands>("- operation: SET\n  arguments:\n    1: {kind: time, formats: [unix_seconds]}\n    1: {kind: time, formats: [unix_seconds]}\n").is_err());
        assert!(serde_yaml::from_str::<Commands>("- operation: SET\n  arguments:\n    1: {kind: time, formats: [unix_seconds]}\n    '1': {kind: time, formats: [unix_seconds]}\n").is_err());
    }
}
