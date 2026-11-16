//! Typed protocol facts consumed by the connection, recording and Replay framework.
use anyhow::{Result, ensure};
use bytes::BytesMut;
use std::any::Any;
use std::sync::Arc;

pub mod connection;
pub mod evidence;
pub mod execution;
mod identity;
pub mod io;
pub mod message;
pub mod observation;
pub mod output;
pub mod transport;
pub use identity::ProtocolId;

/// A process-local provider factory. Connection ownership, scheduling and
/// persistence belong to the framework.
pub trait DependencyProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }
    fn recognize(&self, probe: Probe<'_>) -> Recognition;
    fn create_session(&self) -> Result<Session>;
    fn evidence(&self) -> Option<Arc<dyn evidence::EvidenceAdapter>> {
        None
    }
    fn native_protocol(&self) -> Option<Arc<dyn connection::NativeProtocol>> {
        None
    }
}

/// One native session interface, erased at the registration boundary and bound
/// once by its protocol adapter before I/O. Frames retain their native types.
pub struct Session {
    native: Box<dyn Any + Send>,
}

impl Session {
    pub fn new<T: Send + 'static>(native: T) -> Self {
        Self {
            native: Box::new(native),
        }
    }

    pub fn bind<T: Send + 'static>(self) -> Result<T> {
        self.native
            .downcast::<T>()
            .map(|native| *native)
            .map_err(|_| {
                anyhow::anyhow!(
                    "provider session does not implement {}",
                    std::any::type_name::<T>()
                )
            })
    }
}

/// Incremental native byte framing. Framework I/O supplies and bounds the buffer.
pub trait FrameDecoder: Send {
    type Frame;
    fn decode(&mut self, input: &mut BytesMut) -> Result<Option<Self::Frame>>;
    fn encode(&self, frame: &Self::Frame, output: &mut BytesMut) -> Result<()>;
    fn read_size(&self, _input: &[u8]) -> Result<usize> {
        Ok(8192)
    }

    fn parse(
        &mut self,
        input: &mut BytesMut,
        handler: &mut dyn EventHandler<Self::Frame>,
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

#[derive(Clone)]
pub struct RegisteredProtocol<Kind> {
    pub kind: Kind,
    pub provider: Arc<dyn DependencyProvider>,
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
        match provider.provider.recognize(probe) {
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
    pub fn new(kind: Kind, provider: Arc<dyn DependencyProvider>) -> Self {
        Self { kind, provider }
    }
}

/// Immutable after startup assembly. Sessions keep using the provider selected
/// for their connection, independently of other recorder or Replay instances.
#[derive(Clone)]
pub struct ProviderRegistry<Kind> {
    providers: Vec<RegisteredProtocol<Kind>>,
    evidence: evidence::EvidenceRegistry,
}

impl<Kind: std::fmt::Debug> std::fmt::Debug for ProviderRegistry<Kind> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_list()
            .entries(
                self.providers
                    .iter()
                    .map(|entry| (&entry.kind, entry.provider.name())),
            )
            .finish()
    }
}

impl<Kind> Default for ProviderRegistry<Kind> {
    fn default() -> Self {
        Self {
            providers: Vec::new(),
            evidence: evidence::EvidenceRegistry::default(),
        }
    }
}

impl<Kind: Copy + PartialEq> ProviderRegistry<Kind> {
    fn validate_names(
        &self,
        provider: &dyn DependencyProvider,
        replaced: Option<usize>,
    ) -> Result<()> {
        let mut names = std::collections::BTreeSet::new();
        for name in std::iter::once(provider.name()).chain(provider.aliases().iter().copied()) {
            ensure!(
                !name.is_empty() && names.insert(name),
                "dependency provider names and aliases must be unique and nonempty"
            );
        }
        for (index, entry) in self.providers.iter().enumerate() {
            if replaced == Some(index) {
                continue;
            }
            ensure!(
                std::iter::once(entry.provider.name())
                    .chain(entry.provider.aliases().iter().copied())
                    .all(|name| !names.contains(name)),
                "dependency provider name or alias is already registered"
            );
        }
        Ok(())
    }
    pub fn register(&mut self, kind: Kind, provider: Arc<dyn DependencyProvider>) -> Result<()> {
        self.validate_names(provider.as_ref(), None)?;
        ensure!(!provider.name().is_empty(), "provider name is empty");
        ensure!(
            self.providers
                .iter()
                .all(|registered| registered.kind != kind
                    && registered.provider.name() != provider.name()),
            "dependency provider is already registered"
        );
        if let Some(adapter) = provider.evidence() {
            self.evidence.register(provider.name(), adapter)?;
        }
        self.providers.push(RegisteredProtocol::new(kind, provider));
        Ok(())
    }

    pub fn recognize(&self, probe: Probe<'_>) -> Result<Detection<Kind>> {
        recognize(&self.providers, probe)
    }

    pub fn replace(&mut self, kind: Kind, provider: Arc<dyn DependencyProvider>) -> Result<()> {
        let index = self
            .providers
            .iter()
            .position(|registered| registered.kind == kind)
            .ok_or_else(|| anyhow::anyhow!("dependency provider is not registered"))?;
        self.validate_names(provider.as_ref(), Some(index))?;
        ensure!(!provider.name().is_empty(), "provider name is empty");
        ensure!(
            self.providers
                .iter()
                .enumerate()
                .all(|(position, registered)| {
                    position == index || registered.provider.name() != provider.name()
                }),
            "dependency provider name is already registered"
        );
        self.evidence.replace(
            self.providers[index].provider.name(),
            provider.name(),
            provider.evidence(),
        )?;
        self.providers[index] = RegisteredProtocol::new(kind, provider);
        Ok(())
    }

    pub fn provider(&self, kind: Kind) -> Result<&Arc<dyn DependencyProvider>> {
        self.providers
            .iter()
            .find(|registered| registered.kind == kind)
            .map(|registered| &registered.provider)
            .ok_or_else(|| anyhow::anyhow!("dependency provider is not registered"))
    }

    pub fn create_session(&self, kind: Kind) -> Result<Session> {
        self.provider(kind)?.create_session()
    }

    pub fn evidence(&self) -> &evidence::EvidenceRegistry {
        &self.evidence
    }

    pub fn registrations(&self) -> &[RegisteredProtocol<Kind>] {
        &self.providers
    }

    pub fn event_provider(&self, event: &serde_json::Value) -> Option<&RegisteredProtocol<Kind>> {
        let owner = self.evidence.owner(event)?;
        self.providers
            .iter()
            .find(|entry| entry.provider.name() == owner)
    }

    pub fn register_evidence(
        &mut self,
        name: &str,
        adapter: Arc<dyn evidence::EvidenceAdapter>,
    ) -> Result<()> {
        ensure!(
            self.providers
                .iter()
                .all(|entry| entry.provider.name() != name),
            "evidence adapter name belongs to a registered connection provider"
        );
        self.evidence.register(name, adapter)
    }
}

#[cfg(test)]
mod tests;

pub mod capture;

pub mod report;
