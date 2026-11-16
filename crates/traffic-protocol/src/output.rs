//! Native response bytes and logical output boundaries supplied to the host.
use crate::connection::ResponseFramer;
use anyhow::Result;
use bytes::Bytes;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputBoundary {
    Headers,
    Part,
    End,
}

pub struct OutputChunk {
    pub bytes: Bytes,
    pub boundary: OutputBoundary,
    /// The last chunk of this logical output event. A Part event can have
    /// several chunks, and a response can contain several complete Part events.
    pub complete: bool,
}

/// A finite native response plan. Encoding owns wire framing and immutable
/// boundary facts. The host owns waits, writes, flushes and delivery receipts.
pub trait OutputStream: Send {
    fn part_count(&self) -> usize;
    fn next(&mut self) -> Result<Option<OutputChunk>>;
    fn written(&mut self, _success: bool) {}
    fn flushed(&mut self, _success: bool) {}
    fn write_context(&self) -> &'static str {
        "failed to write native response"
    }
    fn flush_context(&self, _boundary: OutputBoundary) -> &'static str {
        "failed to flush native response"
    }
}

pub struct SingleOutput(Option<Bytes>);

/// An owned finite chunk plan retains native boundaries until actual delivery.
pub struct BufferedOutput {
    parts: usize,
    chunks: VecDeque<OutputChunk>,
}

impl BufferedOutput {
    pub fn new(parts: usize, chunks: impl IntoIterator<Item = OutputChunk>) -> Self {
        Self {
            parts,
            chunks: chunks.into_iter().collect(),
        }
    }
}

impl OutputStream for BufferedOutput {
    fn part_count(&self) -> usize {
        self.parts
    }

    fn next(&mut self) -> Result<Option<OutputChunk>> {
        Ok(self.chunks.pop_front())
    }
}

/// Apply connection-local native framing while retaining the original logical
/// boundaries and the encoder's write observations.
pub struct FramedOutput<'a> {
    output: Box<dyn OutputStream>,
    framer: &'a mut dyn ResponseFramer,
}

impl<'a> FramedOutput<'a> {
    pub fn new(output: Box<dyn OutputStream>, framer: &'a mut dyn ResponseFramer) -> Self {
        Self { output, framer }
    }
}

impl OutputStream for FramedOutput<'_> {
    fn part_count(&self) -> usize {
        self.output.part_count()
    }
    fn next(&mut self) -> Result<Option<OutputChunk>> {
        let Some(mut chunk) = self.output.next()? else {
            return Ok(None);
        };
        chunk.bytes = self.framer.frame(chunk.bytes)?;
        Ok(Some(chunk))
    }
    fn written(&mut self, success: bool) {
        self.output.written(success);
    }
    fn flushed(&mut self, success: bool) {
        self.output.flushed(success);
    }
    fn write_context(&self) -> &'static str {
        self.output.write_context()
    }
    fn flush_context(&self, boundary: OutputBoundary) -> &'static str {
        self.output.flush_context(boundary)
    }
}

impl SingleOutput {
    pub fn new(bytes: Bytes) -> Self {
        Self(Some(bytes))
    }
}

impl OutputStream for SingleOutput {
    fn part_count(&self) -> usize {
        0
    }

    fn next(&mut self) -> Result<Option<OutputChunk>> {
        Ok(self.0.take().map(|bytes| OutputChunk {
            bytes,
            boundary: OutputBoundary::End,
            complete: true,
        }))
    }
}
