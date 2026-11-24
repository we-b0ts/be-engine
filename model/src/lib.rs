//! Recording identities, ownership and observable dependency outcomes.
pub mod attribution;
mod outcome;
pub mod recording;
mod reference;
pub mod session;
pub mod trace;

pub use outcome::*;

pub mod capture;
