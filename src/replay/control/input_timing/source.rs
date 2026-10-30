//! Immutable input timing and protocol coverage, without expected output values.
use super::*;
use crate::interaction::model::{InputTranscript, Protocol};
use std::io::BufReader;

#[derive(Debug)]
pub(super) struct Plan {
    pub input: InputTranscript,
    pub source_start: Option<DateTime<Utc>>,
    pub covered: bool,
}

#[derive(Deserialize)]
struct Request {
    timestamp: Option<DateTime<Utc>>,
    interaction: InputTranscript,
}

pub(super) fn load(case: &ReplayCase) -> Result<Plan> {
    let raw = crate::request_headers::load_request_file(&case.dir.join("request.json"))?;
    let request: Request = serde_json::from_slice(&raw)?;
    request.interaction.validate()?;
    ensure!(
        request.interaction.protocol == Protocol::SocketIo,
        "input timing requires Socket.IO"
    );
    // Other protocols retain recorded timing until their actual delivery
    // adapters exist. Their claim/consumed state is not a delivery substitute.
    let file = std::fs::File::open(&case.dependencies_path)?;
    let mut covered = request.timestamp.is_some();
    #[derive(Deserialize)]
    struct Kind {
        event_type: String,
    }
    // Deserialize only the kind; large authenticated carrier strings are
    // skipped by serde rather than retained as timing-plan values.
    for kind in serde_json::Deserializer::from_reader(BufReader::new(file)).into_iter::<Kind>() {
        let kind = kind?;
        covered &= matches!(
            kind.event_type.as_str(),
            "redis_exchange" | "redis_pub_sub_push"
        );
    }
    Ok(Plan {
        input: request.interaction,
        source_start: request.timestamp,
        covered,
    })
}
