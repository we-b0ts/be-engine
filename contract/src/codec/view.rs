//! Borrowed logical payload access; no native request serialization is required.
use super::CodecKind;
use serde_json::Value;

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Absent,
    Present,
}

#[derive(Debug, Clone)]
pub struct ValueView<'a> {
    kind: CodecKind,
    value: &'a Value,
}
impl<'a> ValueView<'a> {
    pub(super) fn new(kind: CodecKind, value: &'a Value) -> Self {
        Self { kind, value }
    }
    pub fn kind(&self) -> CodecKind {
        self.kind.clone()
    }
    pub fn logical(&self) -> &'a Value {
        self.value
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn at(&self, pointer: &str) -> Option<Self> {
        self.value.pointer(pointer).map(|value| Self {
            kind: self.kind.clone(),
            value,
        })
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn presence(&self, pointer: &str) -> Presence {
        if self.at(pointer).is_some() {
            Presence::Present
        } else {
            Presence::Absent
        }
    }
}
