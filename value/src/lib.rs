//! Format-independent values and extension contracts for traffic execution.
pub mod codec;
mod patch;
pub mod path;
pub mod schema;
mod transformation;
mod value;

pub use patch::validate_patch;
pub use transformation::transformation_paths;
pub use value::{Number, Value};

pub const MAX_VALUE_BYTES: usize = 64 * 1024 * 1024;

pub mod selector_map;
