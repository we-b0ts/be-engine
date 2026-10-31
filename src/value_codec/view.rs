//! Borrowed logical payload access; no native request serialization is required.
use super::CodecKind;
use serde_json::Value;

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Presence {
    Absent,
    Present,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ValueView<'a> {
    kind: CodecKind,
    value: &'a Value,
}
impl<'a> ValueView<'a> {
    pub(super) fn new(kind: CodecKind, value: &'a Value) -> Self {
        Self { kind, value }
    }
    pub(crate) fn kind(self) -> CodecKind {
        self.kind
    }
    pub(crate) fn logical(self) -> &'a Value {
        self.value
    }
    #[cfg(test)]
    pub(crate) fn at(self, pointer: &str) -> Option<Self> {
        self.value.pointer(pointer).map(|value| Self {
            kind: self.kind,
            value,
        })
    }
    #[cfg(test)]
    pub(crate) fn presence(self, pointer: &str) -> Presence {
        if self.at(pointer).is_some() {
            Presence::Present
        } else {
            Presence::Absent
        }
    }
}
