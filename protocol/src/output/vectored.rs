//! Write complete native frames through a direct, vectored transport.
use std::io::{Error, ErrorKind, IoSlice};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;

use crate::connection::OutputIo;

pub const MAX_MESSAGE_BATCH_FRAMES: usize = 16;

pub struct BatchWrite {
    /// Complete frames accepted by the direct transport before any error.
    pub completed_frames: usize,
    /// Calls to the async vectored write interface.
    pub writes: usize,
    pub error: Option<Error>,
}

pub async fn write_message_batch(io: &mut dyn OutputIo, frames: &[Bytes]) -> BatchWrite {
    let mut result = BatchWrite {
        completed_frames: 0,
        writes: 0,
        error: None,
    };
    if frames.is_empty() {
        return result;
    }
    if frames.len() > MAX_MESSAGE_BATCH_FRAMES || frames.iter().any(Bytes::is_empty) {
        result.error = Some(Error::new(
            ErrorKind::InvalidInput,
            "invalid native frame batch",
        ));
        return result;
    }
    let mut slices = [IoSlice::new(&[]); MAX_MESSAGE_BATCH_FRAMES];
    for (slice, frame) in slices.iter_mut().zip(frames) {
        *slice = IoSlice::new(frame);
    }
    let mut remaining = &mut slices[..frames.len()];
    while !remaining.is_empty() {
        result.writes += 1;
        match io.write_vectored(remaining).await {
            Ok(0) => {
                result.error = Some(Error::new(
                    ErrorKind::WriteZero,
                    "native frame batch write stalled",
                ));
                return result;
            }
            Ok(written) => IoSlice::advance_slices(&mut remaining, written),
            Err(error) => {
                result.error = Some(error);
                return result;
            }
        }
        result.completed_frames = frames.len() - remaining.len();
    }
    result.error = io.flush().await.err();
    result
}

#[cfg(test)]
mod tests;
