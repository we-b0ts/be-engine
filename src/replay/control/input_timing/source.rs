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

pub(super) fn load(
    case: &ReplayCase,
    fast_cap: Option<u64>,
    prepared_dependencies: Option<&[u8]>,
) -> Result<Plan> {
    let raw = crate::request_headers::load_request_file(&case.dir.join("request.json"))?;
    let request: Request = serde_json::from_slice(&raw)?;
    request.interaction.validate()?;
    ensure!(
        request.interaction.protocol == Protocol::SocketIo,
        "input timing requires Socket.IO"
    );
    // Other protocols retain recorded timing until their actual delivery
    // adapters exist. Their claim/consumed state is not a delivery substitute.
    let mut covered = request.timestamp.is_some();
    let mut fast = fast_cap
        .zip(request.timestamp)
        .filter(|_| !request.interaction.policy.preserve_input_timing)
        .map(|(cap, start)| fast::Source::new(&case.dir, &request.interaction, cap, start));
    #[derive(Deserialize)]
    struct Kind {
        event_type: String,
    }
    let mut observe = |raw: &[u8]| -> Result<()> {
        if raw.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let kind: Kind = serde_json::from_slice(raw)?;
        covered &= matches!(
            kind.event_type.as_str(),
            "redis_exchange" | "redis_pub_sub_push"
        );
        if let Some(fast) = fast.as_mut() {
            fast.record(raw)?;
        }
        Ok(())
    };
    // Deferred preparation already authenticated the frozen scope. Reuse
    // those bytes instead of traversing the recording again after admission.
    if let Some(bytes) = prepared_dependencies {
        for raw in bytes.split(|byte| *byte == b'\n') {
            observe(raw)?;
        }
    } else {
        let mut records = crate::dependency_index::RecordStream::open(&case.dependencies_path)?;
        while let Some((_, raw)) = records.next()? {
            observe(raw)?;
        }
    }
    Ok(Plan {
        input: request.interaction,
        source_start: request.timestamp,
        covered,
        fast,
    })
}
