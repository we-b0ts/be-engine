//! Typed recording payloads and the globally ordered event envelope.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::DependencyExchangeOutcome;
use crate::recording::{CapturePhase, ProtocolRef};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutputKind {
    Headers,
    Part,
    End,
    NoResponse,
    TargetStop,
    Terminated {
        termination: crate::DependencyTermination,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    Request,
    Message,
    Upgrade,
    ClientClose,
    TransportEnd,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimaryBoundary {
    Start,
    ResponseEnd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum CaptureEvent {
    PrimaryBoundary {
        case_id: Uuid,
        boundary: PrimaryBoundary,
    },
    #[serde(rename = "message_started")]
    MessageStarted { dependency_sequence: u64 },
    #[serde(rename = "wire_output_started")]
    OutputStarted {
        dependency_sequence: u64,
        output: OutputKind,
    },
    #[serde(rename = "wire_output_cancelled")]
    OutputCancelled {
        dependency_sequence: u64,
        started_sequence: u64,
    },
    #[serde(rename = "primary_input")]
    Input {
        case_id: Uuid,
        input_sequence: u64,
        kind: InputKind,
    },
    #[serde(rename = "wire_output")]
    Output {
        dependency_sequence: u64,
        output: OutputKind,
    },
    #[serde(rename = "capture_started")]
    Started {
        dependency_sequence: u64,
        phase: CapturePhase,
        observed_case: Option<Uuid>,
        admitted_case: Option<Uuid>,
    },
    #[serde(rename = "capture_bound")]
    Bound {
        exchange_id: Uuid,
        dependency_sequence: u64,
        protocol_ref: ProtocolRef,
    },
    #[serde(rename = "capture_terminated")]
    Terminal {
        dependency_sequence: u64,
        outcome: String,
        capture_complete: bool,
    },
    #[serde(rename = "capture_sealed")]
    Sealed,
}

impl CaptureEvent {
    pub fn dependency_sequence(&self) -> Option<u64> {
        match self {
            Self::Started {
                dependency_sequence,
                ..
            }
            | Self::MessageStarted {
                dependency_sequence,
                ..
            }
            | Self::OutputStarted {
                dependency_sequence,
                ..
            }
            | Self::OutputCancelled {
                dependency_sequence,
                ..
            }
            | Self::Output {
                dependency_sequence,
                ..
            }
            | Self::Bound {
                dependency_sequence,
                ..
            }
            | Self::Terminal {
                dependency_sequence,
                ..
            } => Some(*dependency_sequence),
            Self::PrimaryBoundary { .. } | Self::Input { .. } | Self::Sealed => None,
        }
    }
}

/// One native dependency call. Its typed payload owns request, response and
/// protocol state. The framework owns identity, attribution and capture integrity.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecordedDependency<Payload> {
    pub recording_id: Uuid,
    pub capture: crate::recording::CaptureMetadata,
    pub outcome: DependencyExchangeOutcome,
    pub capture_complete: bool,
    #[serde(flatten)]
    pub payload: Payload,
}

/// An observed event in one recording's monotonic order. The payload identifies
/// its dependency or connection and supplies its protocol-independent event kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedEvent<Event> {
    pub sequence: u64,
    pub offset_micros: u64,
    #[serde(flatten)]
    pub event: Event,
}
