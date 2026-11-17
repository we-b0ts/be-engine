//! Finite references resolve through protocol capabilities and shared delivery state.
use super::{ReplayExchangeStatus, ReplayProtocolSet, RuntimeState};
use anyhow::{Result, ensure};
use traffic_protocol::ProtocolId;

pub(crate) use traffic_model::recording::ProtocolRef as RecordedReference;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProtocolExchange {
    pub inventory: ProtocolId,
    pub index: usize,
}

/// Handles retain their inventory owner. Resolving a reference never claims it.
#[derive(Debug, Clone, Copy)]
pub(in crate::replay) enum ExchangeHandle {
    Registered(usize),
    Native(ProtocolExchange),
    Connect(usize),
}

pub(in crate::replay) fn resolve_case<P: ReplayProtocolSet, T>(
    state: &RuntimeState<P>,
    case: &str,
    references: &[RecordedReference],
    project: impl Fn(RecordedReference, ExchangeHandle) -> T,
) -> Result<Vec<T>> {
    let mut native_indices = Vec::with_capacity(references.len());
    let mut protocol_refs = Vec::new();
    for reference in references {
        let native = state.native.core.resolve_reference(case, reference)?;
        if native.is_none() && !matches!(reference.protocol(), "capture" | "connect") {
            protocol_refs.push(reference.clone());
        }
        native_indices.push(native);
    }
    let resolved = P::resolve_references(state, case, &protocol_refs)?;
    ensure!(
        resolved.len() == protocol_refs.len(),
        "native finite reference resolution returned a different inventory length"
    );
    let mut resolved = resolved.into_iter();

    references
        .iter()
        .zip(native_indices)
        .map(|(reference, native)| {
            let handle = if let Some(index) = native {
                ExchangeHandle::Registered(index)
            } else {
                match reference.protocol() {
                    "capture" => {
                        #[derive(serde::Deserialize)]
                        #[serde(deny_unknown_fields)]
                        struct Identity {
                            exchange_id: uuid::Uuid,
                        }
                        let identity: Identity = reference.identity()?;
                        ExchangeHandle::Registered(
                            state.native.resolve(case, identity.exchange_id)?,
                        )
                    }
                    "connect" => {
                        #[derive(serde::Deserialize)]
                        #[serde(deny_unknown_fields)]
                        struct Identity {
                            event_id: uuid::Uuid,
                        }
                        let identity: Identity = reference.identity()?;
                        ExchangeHandle::Connect(
                            state.connect_failures.resolve(case, identity.event_id)?,
                        )
                    }
                    _ => ExchangeHandle::Native(
                        resolved.next().expect("native reference count checked"),
                    ),
                }
            };
            Ok(project(reference.clone(), handle))
        })
        .collect()
}

impl ExchangeHandle {
    pub(in crate::replay) fn permits_cancelled_omission<P: ReplayProtocolSet>(
        self,
        state: &RuntimeState<P>,
    ) -> bool {
        match self {
            Self::Native(exchange) => P::permits_cancelled_omission(state, exchange),
            Self::Connect(_) | Self::Registered(_) => false,
        }
    }

    pub(in crate::replay) fn shared_initialization<P: ReplayProtocolSet>(
        self,
        state: &RuntimeState<P>,
        completion: &crate::recorder::async_api::CompletionRequirements,
    ) -> bool {
        match self {
            Self::Native(exchange) => P::shared_initialization(state, exchange, completion),
            _ => false,
        }
    }

    pub(in crate::replay) fn delivery_state<P: ReplayProtocolSet>(
        self,
        state: &RuntimeState<P>,
    ) -> Option<ReplayExchangeStatus> {
        match self {
            Self::Native(exchange) => P::exchange_status(state, exchange),
            Self::Connect(index) => state.connect_failures.status(index),
            Self::Registered(index) => state.native.core.exchanges.get(index).map(|exchange| {
                state
                    .native
                    .core
                    .lifecycle
                    .live_status(index, exchange.status)
            }),
        }
    }

    pub(in crate::replay) fn permits_unstarted_omission<P: ReplayProtocolSet>(
        self,
        state: &RuntimeState<P>,
        shared_initialization: bool,
        strict_reference: bool,
    ) -> bool {
        match self {
            Self::Native(exchange) => P::permits_unstarted_omission(
                state,
                exchange,
                shared_initialization,
                strict_reference,
            ),
            Self::Connect(_) | Self::Registered(_) => false,
        }
    }
}
