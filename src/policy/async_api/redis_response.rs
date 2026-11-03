//! Native Redis reply predicates, separate from request message conditions.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "ResponseDocument", into = "ResponseDocument")]
pub enum AsyncRedisResponse {
    #[default]
    Any,
    Nil,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseDocument {
    kind: ResponseKind,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResponseKind {
    Any,
    Nil,
}

impl From<ResponseDocument> for AsyncRedisResponse {
    fn from(document: ResponseDocument) -> Self {
        match document.kind {
            ResponseKind::Any => Self::Any,
            ResponseKind::Nil => Self::Nil,
        }
    }
}

impl From<AsyncRedisResponse> for ResponseDocument {
    fn from(condition: AsyncRedisResponse) -> Self {
        Self {
            kind: match condition {
                AsyncRedisResponse::Any => ResponseKind::Any,
                AsyncRedisResponse::Nil => ResponseKind::Nil,
            },
        }
    }
}

impl AsyncRedisResponse {
    pub(crate) fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }
}

#[cfg(test)]
mod tests;
