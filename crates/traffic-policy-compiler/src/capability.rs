//! Capability requirements are semantic and typed, never protocol-specific lists.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub mod coverage;
pub use coverage::{validate_actual_protocol, validate_native_coverage, validate_rule_coverage};

use super::{Codec, FieldContract};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityId {
    Exact,
    Registered,
    Unordered,
    RelativeTime,
    Duration,
    RebaseTime,
    Identity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldRequirement {
    PolicyDefined,
    Collection,
    Timestamp,
    Number,
    DeclaredTimestamp,
    IdentityString,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Capability {
    pub id: CapabilityId,
    pub version: u32,
    pub field_requirement: FieldRequirement,
    pub source_proof: &'static [&'static str],
}

const CAPABILITIES: &[Capability] = &[
    Capability {
        id: CapabilityId::Exact,
        version: 1,
        field_requirement: FieldRequirement::PolicyDefined,
        source_proof: &[],
    },
    Capability {
        id: CapabilityId::Registered,
        version: 1,
        field_requirement: FieldRequirement::PolicyDefined,
        source_proof: &["Source semantics and the registered policy's configuration requirements"],
    },
    Capability {
        id: CapabilityId::Identity,
        version: 1,
        field_requirement: FieldRequirement::IdentityString,
        source_proof: &[
            "Source generation or derivation of a fresh identity and its exact representation",
            "shared binding identifies the same entity across SSE messages; external identity relationships remain obligations",
        ],
    },
    Capability {
        id: CapabilityId::Unordered,
        version: 1,
        field_requirement: FieldRequirement::Collection,
        source_proof: &["Source collection construction and downstream use do not require order"],
    },
    Capability {
        id: CapabilityId::RelativeTime,
        version: 1,
        field_requirement: FieldRequirement::Timestamp,
        source_proof: &[
            "Source timestamp generation or offset semantics",
            "timestamp representation and clock anchor",
        ],
    },
    Capability {
        id: CapabilityId::Duration,
        version: 1,
        field_requirement: FieldRequirement::Number,
        source_proof: &[
            "Source elapsed-duration calculation and unit",
            "clock anchor",
        ],
    },
    Capability {
        id: CapabilityId::RebaseTime,
        version: 1,
        field_requirement: FieldRequirement::DeclaredTimestamp,
        source_proof: &[
            "recorded timestamp must move with the declared clock anchor",
            "downstream identity, signature and encryption compatibility",
        ],
    },
];

pub fn capabilities() -> &'static [Capability] {
    CAPABILITIES
}

impl CapabilityId {
    pub fn for_contract(contract: &FieldContract) -> Self {
        match contract {
            FieldContract::Exact => Self::Exact,
            FieldContract::Policy(_) => Self::Registered,
            FieldContract::Conditional { contract, .. } => Self::for_contract(contract),
            FieldContract::Unordered => Self::Unordered,
            FieldContract::Time { .. } => Self::RelativeTime,
            FieldContract::Duration { .. } => Self::Duration,
            FieldContract::Identity { .. } | FieldContract::IdentityAnchor => Self::Identity,
        }
    }

    pub fn descriptor(self) -> &'static Capability {
        CAPABILITIES
            .iter()
            .find(|capability| capability.id == self)
            .expect("every closed capability has one registered descriptor")
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Registered => "registered",
            Self::Unordered => "unordered",
            Self::RelativeTime => "relative_time",
            Self::Duration => "duration",
            Self::RebaseTime => "rebase_time",
            Self::Identity => "identity",
        }
    }
}

/// Codec owners describe fields. Registered policy owners validate their own
/// requirements against that description before evidence materialization.
pub fn validate_contract_binding(
    codec: &Codec,
    path: &str,
    contract: &FieldContract,
    context: &crate::CompilationContext<'_>,
) -> Result<()> {
    let configuration = serde_json::from_value(codec.configuration().clone())?;
    if let FieldContract::Conditional { when, contract } = contract {
        let pointer = when
            .peer_pointer(path)
            .ok_or_else(|| anyhow::anyhow!("conditional field has no parent"))?;
        let sibling = context
            .codecs
            .field_schema(codec.id(), &configuration, &pointer)?;
        for expected in when.values() {
            let expected = serde_json::from_value(serde_json::to_value(expected)?)?;
            ensure!(
                sibling.accepts_literal(&expected),
                "Source condition and declared sibling types disagree"
            );
        }
        return validate_contract_binding(codec, path, contract, context);
    }
    let schema = context
        .codecs
        .field_schema(codec.id(), &configuration, path)?;
    if let Some(definition) = contract.registered_definition(false) {
        context
            .policies
            .prepare_definition(&definition)?
            .validate_schema(&schema)?;
    }
    Ok(())
}

pub use coverage::{ValueCoordinate, value_capability_support};
