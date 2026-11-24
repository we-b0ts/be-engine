//! Source process and primary HTTP events in a recording session.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionEvent {
    SourceStart,
    Ready,
    Stop,
    SourceExit {
        status: Option<i32>,
    },
    PrimaryRequest {
        exchange: Uuid,
        request: Value,
    },
    PrimaryResponseHeaders {
        exchange: Uuid,
        response: Value,
    },
    PrimaryResponsePart {
        exchange: Uuid,
        part: u64,
        data_base64: String,
    },
    PrimaryResponseTrailers {
        exchange: Uuid,
        trailers: Value,
    },
    PrimaryResponseEnd {
        exchange: Uuid,
    },
    PrimaryCancel {
        exchange: Uuid,
        reason: String,
    },
}

impl SessionEvent {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::SourceStart => "source_start",
            Self::Ready => "ready",
            Self::Stop => "stop",
            Self::SourceExit { .. } => "source_exit",
            Self::PrimaryRequest { .. } => "primary_request",
            Self::PrimaryResponseHeaders { .. } => "primary_response_headers",
            Self::PrimaryResponsePart { .. } => "primary_response_part",
            Self::PrimaryResponseTrailers { .. } => "primary_response_trailers",
            Self::PrimaryResponseEnd { .. } => "primary_response_end",
            Self::PrimaryCancel { .. } => "primary_cancel",
        }
    }
}
