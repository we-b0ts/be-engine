//! Target input execution. This owner never opens expected-response evidence.
pub mod event_order;
mod feedback;
pub mod heartbeat_tail;
mod http;
mod socketio;
pub mod timing;
pub use feedback::{Feedback, NativeEvent, NativeEventSink};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use std::time::Duration;

use super::model::{InputTranscript, OutputObservation, Protocol};
use crate::events::HeaderMapSnapshot;

type HttpClient = Client<HttpConnector, Full<Bytes>>;

pub struct ReplayResponse {
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    pub status: StatusCode,
    pub headers: HeaderMapSnapshot,
    pub body: Bytes,
    pub observation: OutputObservation,
}

pub async fn execute(
    client: &HttpClient,
    origin: &str,
    request: Request<Full<Bytes>>,
    transcript: &InputTranscript,
    header_timeout: Duration,
    body_limit: usize,
    feedback: Feedback,
) -> Result<ReplayResponse> {
    transcript.validate()?;
    match transcript.protocol {
        Protocol::SocketIo | Protocol::WebSocket => {
            socketio::execute_with_feedback(
                client,
                origin,
                request,
                transcript,
                header_timeout,
                feedback,
            )
            .await
        }
        _ => {
            http::execute_with_feedback(
                client,
                request,
                transcript,
                header_timeout,
                body_limit,
                feedback,
            )
            .await
        }
    }
}

pub(super) fn elapsed_ms(started: tokio::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
