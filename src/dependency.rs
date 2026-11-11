pub(crate) mod attribution;
pub(crate) mod execution;
pub(crate) mod http_limits;
pub(crate) mod observation;
pub(crate) mod termination;

pub use traffic_model::{
    DependencyExchangeOutcome, DependencyTermination, DiscoveredTcpTarget, TerminationKind,
    TerminationScope, TerminationSide,
};

#[cfg(test)]
mod tests;
