//! Closed schema traversal: authoring defaults never recurse into business data.
use anyhow::{Context, Result, ensure};
use serde_yaml::{Mapping, Value};

use super::{contracts, proof};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Leaf,
    Time,
    SqlValue,
    SqlTime,
    GeneratedValue,
    GeneratedResponse,
    Plaintext,
    SequenceArgument,
    SequenceField,
    SequenceCommand,
    IdentityCapture,
    PathSegment,
    PathField,
    Origin,
    ProcessSelector,
    CaptureResponse,
}

pub fn expand_rule(value: &mut Value, revision: Option<&str>) -> Result<()> {
    rule_with_revision(value, revision, false, false)
}
pub fn compact_rule(value: &mut Value, revision: Option<&str>) -> Result<()> {
    rule_with_revision(value, revision, true, false)
}

/// Source evidence belongs to a plan proposal, independently of the runtime
/// policy produced by rendering that proposal.
pub fn require_source_proof(value: &mut Value, revision: Option<&str>) -> Result<()> {
    rule_with_revision(value, revision, false, true)
}

pub fn rule_with_revision(
    value: &mut Value,
    revision: Option<&str>,
    compact: bool,
    require_proof: bool,
) -> Result<()> {
    // Independent task selectors survive Source upgrades. Evidence keeps its
    // own revision, which also defaults nested proofs within this owner.
    let independent = value.get("effect").is_some_and(|effect| {
        effect.get("kind").and_then(Value::as_str) == Some("process_owned")
            && effect.get("origin").is_none_or(Value::is_null)
            && effect.get("task_name").and_then(Value::as_str).is_some()
    });
    let local = if independent {
        let own = value
            .get("proof")
            .and_then(|proof| proof.get("source"))
            .map(|source| crate::proof::deserialize_source(source.clone()))
            .transpose()?;
        own.as_deref()
            .and_then(|source| source.rsplit_once(" @ "))
            .map(|(_, revision)| revision.to_owned())
            .or_else(|| {
                value
                    .get("effect")
                    .and_then(|effect| effect.get("source_revision"))
                    .and_then(Value::as_str)
                    .filter(|revision| !revision.is_empty())
                    .map(str::to_owned)
            })
    } else {
        None
    };
    Walker {
        revision: local.as_deref().or(revision),
        compact,
        require_proof,
    }
    .rule(value)?;
    Ok(())
}

pub struct Walker<'a> {
    pub revision: Option<&'a str>,
    pub compact: bool,
    pub require_proof: bool,
}

impl Walker<'_> {
    fn rule(&self, value: &mut Value) -> Result<()> {
        let map = value.as_mapping_mut().context("rule must be a mapping")?;
        let capture = map
            .get("effect")
            .and_then(|effect| effect.get("kind"))
            .and_then(Value::as_str)
            == Some("capture_http");
        let raw = map.remove("proof");
        let own = if capture {
            proof::expand_capture(raw, self.revision)?
        } else {
            proof::expand(raw, None, self.revision)?
        };
        ensure!(
            !self.require_proof || !own.is_null(),
            "rule plan requires independent Source proof for each proposed native rule"
        );
        if let Some(effect) = map.get_mut("effect") {
            self.effect(effect, &own)?;
        }
        if !self.compact && !own.is_null() {
            map.insert("proof".into(), own);
        }
        Ok(())
    }

    fn proven(&self, value: &mut Value, shape: Shape, parent: &Value, depth: usize) -> Result<()> {
        ensure!(depth < 128, "authoring contract nesting exceeds 128 levels");
        let mut raw = std::mem::replace(value, Value::Null);
        let local = raw.as_mapping_mut().and_then(|map| map.remove("proof"));
        let own = proof::expand(local, Some(parent), self.revision)?;
        let mut contract = if let Some(map) = raw.as_mapping_mut()
            && let Some(contract) = map.remove("contract")
        {
            ensure!(
                map.is_empty(),
                "a contract/proof wrapper cannot contain other fields"
            );
            contract
        } else {
            raw
        };
        ensure!(
            !self.require_proof || !own.is_null(),
            "rule plan requires Source proof for every declared permission"
        );
        self.node(&mut contract, shape, &own, depth + 1)?;
        if self.compact {
            *value = contract;
        } else {
            let mut map = Mapping::new();
            map.insert("contract".into(), contract);
            if !own.is_null() {
                map.insert("proof".into(), own);
            }
            *value = Value::Mapping(map);
        }
        Ok(())
    }

    fn fields(
        &self,
        value: &mut Value,
        shape: Shape,
        proven: bool,
        parent: &Value,
        depth: usize,
    ) -> Result<()> {
        let map = value
            .as_mapping_mut()
            .context("contract fields require a selector mapping")?;
        for (_, value) in map.iter_mut() {
            if proven {
                self.proven(value, shape, parent, depth + 1)?;
            } else {
                self.node(value, shape, parent, depth + 1)?;
            }
        }
        Ok(())
    }
    fn field_map(
        &self,
        map: &mut Mapping,
        key: &str,
        shape: Shape,
        parent: &Value,
        depth: usize,
    ) -> Result<()> {
        if let Some(value) = map.get_mut(key) {
            self.fields(value, shape, true, parent, depth)?;
        }
        Ok(())
    }
    fn list(
        &self,
        map: &mut Mapping,
        key: &str,
        shape: Shape,
        proven: bool,
        parent: &Value,
        depth: usize,
    ) -> Result<()> {
        if let Some(value) = map.get_mut(key) {
            for entry in value
                .as_sequence_mut()
                .context("contract collection requires a list")?
            {
                if proven {
                    self.proven(entry, shape, parent, depth + 1)?;
                } else {
                    self.node(entry, shape, parent, depth + 1)?;
                }
            }
        }
        Ok(())
    }
    fn one(
        &self,
        map: &mut Mapping,
        key: &str,
        shape: Shape,
        proven: bool,
        parent: &Value,
        depth: usize,
    ) -> Result<()> {
        if let Some(value) = map.get_mut(key) {
            if proven {
                self.proven(value, shape, parent, depth + 1)?;
            } else {
                self.node(value, shape, parent, depth + 1)?;
            }
        }
        Ok(())
    }

    fn effect(&self, value: &mut Value, parent: &Value) -> Result<()> {
        let map = value.as_mapping_mut().context("effect must be a mapping")?;
        match map.get("kind").and_then(Value::as_str).unwrap_or("") {
            "identity" => {
                self.one(map, "capture", Shape::IdentityCapture, false, parent, 0)?;
                self.list(map, "references", Shape::Leaf, true, parent, 0)?;
            }
            "redis_sequence" => {
                self.one(map, "key", Shape::Leaf, true, parent, 0)?;
                self.list(map, "commands", Shape::SequenceCommand, false, parent, 0)?;
            }
            "response_jwt" => self.list(map, "nonces", Shape::Leaf, true, parent, 0)?,
            "response_header_date" => {
                if let Some(offset) = map.remove("timezone") {
                    contracts::validate_legacy_offset(&offset)?;
                }
            }
            "response_generated" => {
                self.field_map(map, "fields", Shape::GeneratedResponse, parent, 0)?
            }
            "response_body" => self.list(map, "fields", Shape::Leaf, true, parent, 0)?,
            "http_request" => {
                self.field_map(map, "headers", Shape::Time, parent, 0)?;
                self.field_map(map, "query", Shape::GeneratedValue, parent, 0)?;
            }
            "mysql_values" => {
                self.field_map(map, "values", Shape::SqlValue, parent, 0)?;
                self.field_map(map, "params", Shape::GeneratedValue, parent, 0)?;
            }
            "capture_http" => proof::source_effect(map, self.revision, self.compact)?,
            "capture_http_response" => {
                self.one(map, "contract", Shape::CaptureResponse, false, parent, 0)?
            }
            "process_owned" => {
                if map.get("origin").is_none_or(Value::is_null)
                    && map.get("task_name").and_then(Value::as_str).is_some()
                {
                    map.remove("source_revision");
                } else {
                    proof::source_effect(map, self.revision, self.compact)?;
                }
                self.one(map, "selector", Shape::ProcessSelector, false, parent, 0)?;
                self.one(map, "origin", Shape::Origin, true, parent, 0)?;
            }
            "finite_sharing" => self.field_map(map, "response_time", Shape::Time, parent, 0)?,
            _ => (), // The selected typed effect rejects unknown kinds/fields below.
        }
        Ok(())
    }

    fn node(&self, value: &mut Value, shape: Shape, parent: &Value, depth: usize) -> Result<()> {
        ensure!(depth < 128, "authoring contract nesting exceeds 128 levels");
        if matches!(
            shape,
            Shape::Time
                | Shape::SqlValue
                | Shape::SqlTime
                | Shape::GeneratedValue
                | Shape::Plaintext
                | Shape::SequenceArgument
                | Shape::SequenceField
        ) {
            contracts::transform(
                value,
                !matches!(shape, Shape::Time | Shape::SqlTime),
                self.compact,
            )?;
        }
        let Some(map) = value.as_mapping_mut() else {
            return Ok(());
        };
        match shape {
            Shape::SqlValue => self.field_map(map, "fields", Shape::SqlTime, parent, depth)?,
            Shape::SequenceArgument => {
                self.field_map(map, "fields", Shape::SequenceField, parent, depth)?
            }
            Shape::SequenceField => {
                self.list(map, "nonces", Shape::Leaf, true, parent, depth)?;
                self.field_map(map, "query", Shape::SequenceField, parent, depth)?;
            }
            Shape::SequenceCommand => {
                self.one(map, "script", Shape::Leaf, true, parent, depth)?;
                self.field_map(map, "arguments", Shape::SequenceArgument, parent, depth)?;
            }
            Shape::IdentityCapture => {
                self.list(map, "copies", Shape::Leaf, true, parent, depth)?;
                self.one(map, "derived_from", Shape::Leaf, true, parent, depth)?;
                self.one(map, "segment", Shape::PathSegment, false, parent, depth)?;
            }
            Shape::PathSegment => self.field_map(map, "fields", Shape::PathField, parent, depth)?,
            Shape::PathField => {
                if self.compact && map.get("kind").and_then(Value::as_str) == Some("timestamp") {
                    if map.get("timezone").and_then(Value::as_str) == Some("UTC") {
                        map.remove("timezone");
                    }
                    if map.get("mode").and_then(Value::as_str) == Some("preserve_or_request_window")
                    {
                        map.remove("mode");
                    }
                }
            }
            Shape::GeneratedResponse => {
                let kind = map.get("kind").and_then(Value::as_str).unwrap_or("");
                let child = if kind == "encrypted_json" {
                    Shape::Plaintext
                } else {
                    Shape::Leaf
                };
                self.field_map(map, "fields", child, parent, depth)?;
            }
            Shape::Origin => self.field_map(map, "capture", Shape::Leaf, parent, depth)?,
            Shape::ProcessSelector => {
                self.list(map, "transaction_members", Shape::Leaf, true, parent, depth)?;
                if map.get("protocol").and_then(Value::as_str) == Some("redis") {
                    self.one(map, "script", Shape::Leaf, true, parent, depth)?;
                }
            }
            Shape::CaptureResponse => {
                self.list(map, "pointers", Shape::Leaf, true, parent, depth)?
            }
            Shape::Leaf
            | Shape::Time
            | Shape::SqlTime
            | Shape::GeneratedValue
            | Shape::Plaintext => (),
        }
        Ok(())
    }
}
