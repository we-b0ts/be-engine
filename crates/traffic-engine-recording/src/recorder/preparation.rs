//! Provider-owned validation of recorded dependencies before Case publication.

pub trait SourcePreparation: Send + Sync {
    fn safety_issue(&self, value: &serde_json::Value) -> Option<String>;
}
