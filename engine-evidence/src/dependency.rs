pub mod attribution;
pub mod execution;
pub mod http_limits;
pub mod observation;
pub mod termination;

pub use traffic_model::{
    DependencyExchangeOutcome, DependencyTermination, DiscoveredTcpTarget, TerminationKind,
    TerminationScope, TerminationSide,
};

#[cfg(test)]
mod tests;
