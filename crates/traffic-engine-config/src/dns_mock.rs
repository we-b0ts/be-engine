mod bypass;
pub use bypass::DomainMatcher;
pub use bypass::normalize_domain;
pub mod registry;
pub use registry::{FakeDnsEntry, FakeDnsRegistry, FakeDnsUpstreamProtocol};
