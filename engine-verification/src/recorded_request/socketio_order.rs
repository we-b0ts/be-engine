//! Project Source wire evidence to timing metadata before Target execution.
use std::{fs::File, io::BufReader, path::Path};

use anyhow::{Result, ensure};

use crate::interaction::{
    model::{OutputObservation, Protocol, TRANSCRIPT_VERSION},
    policy::InteractionPolicy,
    replay::event_order::{Checkpoint, EventKey, Order},
    socketio::{EngineIoPacket, SocketIoDecoder},
};

pub(super) fn load(
    request: &Path,
    policy: &InteractionPolicy,
    last_input: u64,
) -> Result<Option<Order>> {
    let path = request.with_file_name("expected-response.json");
    let path = if path.exists() {
        path
    } else {
        request.with_file_name("expected_response.json")
    };
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut response: serde_json::Value = serde_json::from_reader(BufReader::new(file))?;
    crate::interaction::private::decrypt_output(&mut response, &path)?;
    let Some(output) = response
        .as_object_mut()
        .and_then(|map| map.remove("interaction"))
    else {
        return Ok(None);
    };
    let output: OutputObservation = serde_json::from_value(output)?;
    if output.protocol != Protocol::SocketIo
        || output.version != TRANSCRIPT_VERSION
        || !output.end.clean
    {
        return Ok(None);
    }
    ensure!(
        output.events.len() <= policy.max_messages
            && output
                .events
                .windows(2)
                .all(|pair| pair[0].offset_ms <= pair[1].offset_ms),
        "invalid Source Socket.IO event timeline"
    );
    let mut decoder = SocketIoDecoder::new(policy.max_message_bytes);
    let mut checkpoints = Vec::new();
    for event in output
        .events
        .into_iter()
        .take_while(|event| event.offset_ms < last_input)
    {
        for packet in decoder.push(&event.message)? {
            if let EngineIoPacket::Message(packet) = packet
                && let Some(key) = EventKey::of(&packet)
            {
                checkpoints.push((
                    key,
                    Checkpoint {
                        sequence: event.sequence,
                        offset_ms: event.offset_ms,
                    },
                ));
            }
        }
    }
    Ok(Some(Order::new(checkpoints)))
}
