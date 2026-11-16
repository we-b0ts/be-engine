//! Compatibility declarations for retired native identity captures.
mod config;
mod path_segment;
mod redis_json;
#[cfg(test)]
pub(crate) use config::validate;
pub use config::{
    DynamicValueCapture, DynamicValueFormat, DynamicValueRule, DynamicValueTarget,
    DynamicValueType, PathSegmentCapture, PathSegmentField, RedisCaptureReference,
    RedisDerivedIdentity,
};
