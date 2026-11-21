//! Application bindings for carrier-independent value formats.
pub use traffic_policy_value::formats::checks;
#[cfg(test)]
pub use traffic_policy_value::formats::looks_like_jwt;
#[cfg(test)]
mod jwt;
pub mod template;
pub mod url;

#[cfg(test)]
mod tests;
