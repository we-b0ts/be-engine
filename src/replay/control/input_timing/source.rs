//! Immutable input timing and protocol coverage, without expected output values.
use super::*;
use crate::interaction::model::{InputTranscript, Protocol};

#[derive(Debug)]
pub(super) struct Plan {
    pub input: InputTranscript,
    pub source_start: Option<DateTime<Utc>>,
    pub covered: bool,
    pub fast: Option<fast::Source>,
}

#[derive(Deserialize)]
struct Request {
    timestamp: Option<DateTime<Utc>>,
    interaction: InputTranscript,
}

pub(super) fn load(case: &ReplayCase, fast_cap: Option<u64>) -> Result<Plan> {
    let raw = crate::request_headers::load_request_file(&case.dir.join("request.json"))?;
    let request: Request = serde_json::from_slice(&raw)?;
    request.interaction.validate()?;
    ensure!(
        request.interaction.protocol == Protocol::SocketIo,
        "input timing requires Socket.IO"
    );
    // Other protocols retain recorded timing until their actual delivery
    // adapters exist. Their claim/consumed state is not a delivery substitute.
    let mut records = crate::dependency_index::RecordStream::open(&case.dependencies_path)?;
    let mut covered = request.timestamp.is_some();
    let mut fast = fast_cap
        .zip(request.timestamp)
        .filter(|_| {
            !request.interaction.policy.preserve_input_timing
                && request
                    .interaction
                    .socket_io_heartbeat
                    .as_ref()
                    .is_none_or(|heartbeat| !heartbeat.responses.is_empty())
        })
        .map(|(cap, start)| fast::Source::new(&case.dir, &request.interaction, cap, start));
    #[derive(Deserialize)]
    struct Kind {
        event_type: String,
    }
    // Prepare once at request admission, following the frozen scope's original
    // offsets. Keep one record buffer and deserialize only its kind; carrier
    // values never enter the live per-input timing plan.
    while let Some((_, raw)) = records.next()? {
        if raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let kind: Kind = serde_json::from_slice(raw)?;
        covered &= matches!(
            kind.event_type.as_str(),
            "redis_exchange" | "redis_pub_sub_push"
        );
        if let Some(fast) = fast.as_mut() {
            fast.record(raw)?;
        }
    }
    Ok(Plan {
        input: request.interaction,
        source_start: request.timestamp,
        covered,
        fast,
    })
}
