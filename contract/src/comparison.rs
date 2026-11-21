//! Original logical positions and bounded value mismatch descriptions.
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Difference {
    pub pointer: String,
    pub reason: String,
}
