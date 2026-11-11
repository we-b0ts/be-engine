//! Typed protocol facts consumed by the connection, recording and Replay framework.
use anyhow::{Result, ensure};
use bytes::BytesMut;

pub mod io;

/// Registration is protocol recognition only. The framework retains connection
/// ownership and selects the native framing adapter after bounded pre-reading.
pub trait DependencyProvider: Send + Sync {
    fn recognize(probe: Probe<'_>) -> Recognition;
}

/// Incremental native byte framing. Framework I/O supplies and bounds the buffer.
pub trait FrameDecoder: DependencyProvider {
    type Frame;
    fn decode(&mut self, input: &mut BytesMut) -> Result<Option<Self::Frame>>;
    fn encode(&self, frame: &Self::Frame, output: &mut BytesMut) -> Result<()>;
    fn read_size(&self, _input: &[u8]) -> Result<usize> {
        Ok(8192)
    }

    fn parse(
        &mut self,
        input: &mut BytesMut,
        handler: &mut impl EventHandler<Self::Frame>,
    ) -> Result<()> {
        if let Some(frame) = self.decode(input)? {
            handler.on_event(frame)?;
        }
        Ok(())
    }
}

/// Typed messages stay opaque to common buffering and persistence.
pub trait EventHandler<Message> {
    fn on_event(&mut self, message: Message) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    Client,
    Server,
}

#[derive(Clone, Copy)]
pub struct Probe<'a> {
    pub peer: Peer,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recognition {
    Match,
    NeedMore,
    Reject,
}

pub struct RegisteredProtocol<Kind> {
    pub kind: Kind,
    pub recognize: fn(Probe<'_>) -> Recognition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detection<Kind> {
    Match(Kind),
    NeedMore,
    Reject,
}

/// Inspect the same bounded prefix for every candidate without consuming I/O.
pub fn recognize<Kind: Copy>(
    providers: &[RegisteredProtocol<Kind>],
    probe: Probe<'_>,
) -> Result<Detection<Kind>> {
    let mut matched = None;
    let mut incomplete = false;
    for provider in providers {
        match (provider.recognize)(probe) {
            Recognition::Match => {
                ensure!(
                    matched.is_none(),
                    "multiple dependency protocols match the connection prefix"
                );
                matched = Some(provider.kind);
            }
            Recognition::NeedMore => incomplete = true,
            Recognition::Reject => (),
        }
    }
    Ok(match matched {
        Some(kind) => Detection::Match(kind),
        None if incomplete => Detection::NeedMore,
        None => Detection::Reject,
    })
}

impl<Kind> RegisteredProtocol<Kind> {
    pub const fn new<P: DependencyProvider>(kind: Kind) -> Self {
        Self {
            kind,
            recognize: P::recognize,
        }
    }
}
