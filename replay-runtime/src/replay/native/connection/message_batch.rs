//! Group ready session pushes at the current global sequence frontier.
use super::*;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::{
    connection::{MessageBatchFramer, OutputIo, RecordedInput},
    output::{MAX_MESSAGE_BATCH_FRAMES, write_message_batch},
};

const MAX_BATCH_BYTES: usize = 128 * 1024;

impl<P: ReplayProtocolSet> Host<P> {
    pub(super) async fn write_message_batch(
        &self,
        anchors: &[ProtocolRef],
        io: &mut dyn OutputIo,
        framer: &mut dyn MessageBatchFramer,
    ) -> Result<bool> {
        let (reservation, ready, prefetch) = {
            let state = self.state.lock().await;
            if state.finalized_at.is_some()
                || state.target_session_stopped
                || state.async_case_quiescing()
            {
                return Ok(false);
            }
            let Some(session) = state.session_events.as_ref() else {
                return Ok(false);
            };
            let Some(prefetch) = &session.prefetch else {
                return Ok(false);
            };
            let dependencies = session
                .runtime
                .message_batch_candidates(MAX_MESSAGE_BATCH_FRAMES);
            if dependencies.len() < 2 {
                return Ok(false);
            }
            let delivered = self.delivered.lock().expect("native delivery anchors");
            if !anchors.iter().all(|anchor| delivered.contains_key(anchor)) {
                return Ok(false);
            }
            let core = &state.native.core;
            let mut first_anchor = None;
            let indices = dependencies.iter().map_while(|&dependency| {
                let index =
                    core.session_message_index(dependency, self.protocol, &self.endpoint, anchors)?;
                let RecordedInput::Emission { after, .. } = &core.exchanges[index].native.input
                else {
                    return None;
                };
                let first = *first_anchor.get_or_insert(after);
                let same_connection = after == first
                    || delivered[first]
                        .lane
                        .as_ref()
                        .is_some_and(|lane| delivered[after].lane.as_ref() == Some(lane));
                same_connection.then_some(index)
            });
            let mut bytes = 0;
            let ready = prefetch.take_ready_batch(indices, |index, loaded| {
                let packet = loaded.batchable_message_packet()?;
                if bytes + packet.len() > MAX_BATCH_BYTES {
                    return None;
                }
                let RecordedInput::Emission { after, .. } = &core.exchanges[index].native.input
                else {
                    return None;
                };
                // Keep the first nonbatchable frame for ordinary delivery, which
                // reports any validation error at that frame's own sequence.
                let frame = framer.frame_message(after, packet.clone()).ok()?;
                let total = bytes.checked_add(frame.len())?;
                if frame.is_empty() || total > MAX_BATCH_BYTES {
                    return None;
                }
                bytes = total;
                Some(frame)
            });
            if ready.is_empty() {
                return Ok(false);
            }
            let reservation = session
                .runtime
                .reserve_message_batch(&dependencies[..ready.len()])?;
            (reservation, ready, prefetch.clone())
        };
        let (ready, frames): (Vec<_>, Vec<_>) = ready
            .into_iter()
            .map(|(index, loaded, frame)| ((index, loaded), frame))
            .unzip();
        let written = write_message_batch(io, &frames).await;
        let mut state = self.state.lock().await;
        let failed = ready
            .get(written.completed_frames)
            .or_else(|| ready.last())
            .and_then(|(index, _)| state.native.recorded_sequence(*index));
        if written.completed_frames == 0 && written.error.is_some() {
            reservation.abort();
        } else {
            let published = reservation.publish_prefix(written.completed_frames)?;
            state.native.core.complete_message_batch(&published)?;
            for (index, loaded) in ready.into_iter().take(written.completed_frames) {
                state.native.commit_batched_message(loaded)?;
                state.native.publish_delivery(index, self.protocol);
            }
        }
        prefetch.record_packet_batch(written.completed_frames, written.writes);
        if let Some(error) = written.error {
            let error = anyhow!(error).context("native message batch wire delivery failed");
            if let Some(session) = &mut state.session_events {
                session.fail(failed, None, &error.to_string());
            }
            return Err(error);
        }
        Ok(true)
    }
}
