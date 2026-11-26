//! Deliver finite native output with shared ordering and actual flush receipts.
use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    time::{Duration, Instant},
};
use traffic_protocol::output::{OutputBoundary, OutputStream};

use crate::{EventKind, SequenceClaim};

/// Publish streamed headers and parts after their actual flush. The caller
/// retains the terminal receipt and the once-only semantic completion.
pub async fn deliver(
    writer: &mut (impl AsyncWrite + Unpin + Send + ?Sized),
    output: &mut (impl OutputStream + ?Sized),
    sequence: Option<&SequenceClaim>,
) -> Result<()> {
    let sequence = sequence.filter(|claim| {
        matches!(
            claim.reserved_kind(),
            Some(EventKind::ResponseHeaders | EventKind::TargetStop)
        )
    });
    let mut cursor = Cursor::new(output.part_count(), sequence);
    while let Some(chunk) = output.next()? {
        let no_bytes = matches!(
            chunk.boundary,
            OutputBoundary::TargetStop | OutputBoundary::ClientTermination
        );
        ensure!(
            !no_bytes || chunk.bytes.is_empty() && chunk.complete,
            "native termination must be a complete, zero-byte boundary"
        );
        cursor.begin(chunk.boundary).await?;
        if chunk.boundary == OutputBoundary::ClientTermination {
            tokio::time::timeout(Duration::from_secs(30), output.wait_for_client_close())
                .await
                .context("client did not close the recorded native response")??;
        } else if !no_bytes {
            let written = writer.write_all(&chunk.bytes).await;
            output.written(written.is_ok());
            written.context(output.write_context())?;
        }
        if chunk.complete {
            cursor.finish(writer, output, chunk.boundary).await?;
        }
    }
    ensure!(
        cursor.ended && cursor.active.is_none(),
        "native response ended without a complete output boundary"
    );
    Ok(())
}

struct Cursor<'a> {
    sequence: Option<&'a SequenceClaim>,
    active: Option<OutputBoundary>,
    headers: bool,
    ended: bool,
    part_count: usize,
    parts: usize,
    part_budget: usize,
    batch_parts: usize,
}

impl<'a> Cursor<'a> {
    fn new(part_count: usize, sequence: Option<&'a SequenceClaim>) -> Self {
        Self {
            sequence,
            active: None,
            headers: false,
            ended: false,
            part_count,
            parts: 0,
            part_budget: 0,
            batch_parts: 0,
        }
    }

    async fn begin(&mut self, boundary: OutputBoundary) -> Result<()> {
        ensure!(!self.ended, "native response has output after its end");
        if let Some(active) = self.active {
            ensure!(
                active == boundary,
                "native response changed an incomplete output boundary"
            );
            return Ok(());
        }
        match boundary {
            OutputBoundary::Headers => {
                ensure!(
                    !self.headers && self.parts == 0,
                    "native response repeated or reordered its headers"
                );
            }
            OutputBoundary::Part => {
                ensure!(
                    self.parts < self.part_count,
                    "native response exceeded its declared part count"
                );
                ensure!(
                    self.sequence.is_none() || self.headers,
                    "native streamed output precedes its headers"
                );
            }
            OutputBoundary::End
            | OutputBoundary::TargetStop
            | OutputBoundary::ClientTermination => {
                ensure!(
                    boundary == OutputBoundary::End || self.sequence.is_some(),
                    "native termination requires recorded headers and parts"
                );
                ensure!(
                    self.parts == self.part_count,
                    "native response omitted declared output parts"
                );
                ensure!(
                    self.sequence.is_none()
                        || self.headers
                        || (boundary == OutputBoundary::TargetStop
                            && self.part_count == 0
                            && self.sequence.is_some_and(
                                |claim| claim.reserved_kind() == Some(EventKind::TargetStop)
                            )),
                    "native streamed response omitted its headers"
                );
            }
        }
        if let Some(sequence) = self.sequence {
            self.reserve(sequence, boundary).await?;
        }
        self.active = Some(boundary);
        Ok(())
    }

    async fn reserve(&mut self, sequence: &SequenceClaim, boundary: OutputBoundary) -> Result<()> {
        if boundary == OutputBoundary::Part && self.part_budget != 0 {
            return Ok(());
        }
        let expected = match boundary {
            OutputBoundary::Headers => EventKind::ResponseHeaders,
            OutputBoundary::Part => EventKind::ResponsePart,
            OutputBoundary::End => EventKind::ResponseEnd,
            OutputBoundary::TargetStop => return sequence.wait_target_stop().await,
            OutputBoundary::ClientTermination => return sequence.wait_client_termination().await,
        };
        sequence
            .wait_delivery(Instant::now() + Duration::from_secs(30))
            .await?;
        ensure!(
            sequence.reserved_kind() == Some(expected),
            "native output differs from its recorded boundary"
        );
        if boundary == OutputBoundary::Part {
            self.part_budget = sequence.consecutive_parts(self.part_count - self.parts);
            ensure!(
                self.part_budget > 0,
                "native output part has no recorded boundary"
            );
        }
        Ok(())
    }

    async fn finish(
        &mut self,
        writer: &mut (impl AsyncWrite + Unpin + Send + ?Sized),
        output: &mut (impl OutputStream + ?Sized),
        boundary: OutputBoundary,
    ) -> Result<()> {
        match boundary {
            OutputBoundary::Headers => {
                if let Some(sequence) = self.sequence {
                    flush(writer, output, boundary).await?;
                    sequence.publish()?;
                }
                self.headers = true;
            }
            OutputBoundary::Part => {
                self.parts += 1;
                if let Some(sequence) = self.sequence {
                    self.part_budget -= 1;
                    self.batch_parts += 1;
                    if self.part_budget == 0 {
                        flush(writer, output, boundary).await?;
                        sequence.publish_parts(self.batch_parts)?;
                        self.batch_parts = 0;
                    }
                }
            }
            OutputBoundary::End
            | OutputBoundary::TargetStop
            | OutputBoundary::ClientTermination => {
                if boundary == OutputBoundary::End {
                    flush(writer, output, boundary).await?;
                }
                self.ended = true;
            }
        }
        self.active = None;
        Ok(())
    }
}

async fn flush(
    writer: &mut (impl AsyncWrite + Unpin + Send + ?Sized),
    output: &mut (impl OutputStream + ?Sized),
    boundary: OutputBoundary,
) -> Result<()> {
    let flushed = writer.flush().await;
    output.flushed(flushed.is_ok());
    flushed.context(output.flush_context(boundary))
}

#[cfg(test)]
mod tests;
