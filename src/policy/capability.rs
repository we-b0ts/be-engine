//! Capability requirements are semantic and typed, never protocol-specific lists.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::{Codec, FieldContract, ProtobufType, TimestampFormat};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityId {
    Unordered,
    RelativeTime,
    Duration,
    RebaseTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldRequirement {
    Collection,
    Timestamp,
    Number,
    DeclaredTimestamp,
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
            FieldContract::Unordered => Self::Unordered,
            FieldContract::Time { .. } => Self::RelativeTime,
            FieldContract::Duration { .. } => Self::Duration,
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
            Self::Unordered => "unordered",
            Self::RelativeTime => "relative_time",
            Self::Duration => "duration",
            Self::RebaseTime => "rebase_time",
        }
    }
}

/// JSON types are checked against actual values by the shared evaluator. Typed
/// Protobuf bindings additionally permit static rejection before evidence access.
pub fn validate_contract_binding(
    codec: &Codec,
    path: &str,
    contract: &FieldContract,
) -> Result<()> {
    let Codec::Protobuf(codec) = codec else {
        return Ok(());
    };
    let field = codec.fields.get(path).ok_or_else(|| {
        anyhow::anyhow!("Protobuf contract {path:?} requires an explicit typed field binding")
    })?;
    match contract {
        FieldContract::Unordered => {
            ensure!(
                field.repeated,
                "unordered requires a repeated Protobuf field at {path:?}"
            );
            ensure!(
                field.field_type != ProtobufType::Bytes,
                "unordered bytes require an explicit payload codec, not inferred text/message semantics"
            );
        }
        FieldContract::Time { format, .. } => {
            ensure!(
                !field.repeated,
                "timestamp requires a scalar Protobuf field at {path:?}"
            );
            let valid = match format {
                TimestampFormat::Rfc3339
                | TimestampFormat::AmzDate
                | TimestampFormat::Iso8601Naive => field.field_type == ProtobufType::String,
                _ => numeric(field.field_type),
            };
            ensure!(
                valid,
                "timestamp format and Protobuf field type disagree at {path:?}"
            );
        }
        FieldContract::Duration { .. } => ensure!(
            !field.repeated && numeric(field.field_type),
            "duration requires a numeric scalar Protobuf field at {path:?}"
        ),
    }
    Ok(())
}

fn numeric(kind: ProtobufType) -> bool {
    matches!(
        kind,
        ProtobufType::Int32
            | ProtobufType::Int64
            | ProtobufType::Uint32
            | ProtobufType::Uint64
            | ProtobufType::Sint32
            | ProtobufType::Sint64
            | ProtobufType::Fixed32
            | ProtobufType::Fixed64
            | ProtobufType::Sfixed32
            | ProtobufType::Sfixed64
            | ProtobufType::Float
            | ProtobufType::Double
    )
}
