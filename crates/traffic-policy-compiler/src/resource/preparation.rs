//! Resource preparation declares the existing native lookup and rule-index needs.
use super::{DependencyProvider, OperationSelector, ResourceProvider};
use crate::{
    Surface,
    plan::{IndexRequirement as I, IndexRequirements, SlotKind},
};
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupPreparation {
    /// Ordered scope/endpoint/operation postings installed by native Case preparation.
    /// Availability and optional lane admission remain live native decisions.
    Indexed,
    /// The existing protocol matcher owns candidate traversal, wire identity and
    /// ordering. This does not promise the HTTP/Redis/MySQL postings or a new index.
    ExistingNative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorPreparation {
    NativeOperation,
    SqlTemplate,
}

#[derive(Debug, Clone, Copy)]
pub struct ResourcePreparationRequest<'a> {
    pub operation: Option<&'a str>,
    pub value_slot: Option<(Surface, SlotKind)>,
    pub semantic_links: bool,
}

#[derive(Debug)]
pub struct ResourcePreparation<'a> {
    pub operation: OperationSelector<'a>,
    pub indexes: IndexRequirements,
    pub lookup: LookupPreparation,
    pub selector: SelectorPreparation,
}

pub fn prepare<'a>(
    provider: ResourceProvider,
    request: ResourcePreparationRequest<'a>,
) -> Result<ResourcePreparation<'a>> {
    let operation = provider.operation(request.operation)?;
    let mut indexes = vec![I::Scope, I::EndpointOperation];
    // HTTP has no connection-lane contract. Kafka pairs produce/fetch/delivery
    // effects with its native request identity, rather than a generic lane index.
    // Memcached/Motan enforce their lane through the existing native matcher;
    // Redis/MySQL use the prepared LaneIndex with the same live admission guards.
    if matches!(
        provider,
        ResourceProvider::Redis
            | ResourceProvider::Mysql
            | ResourceProvider::Memcached
            | ResourceProvider::Motan
    ) {
        indexes.push(I::SessionOrder);
    }
    if let Some((surface, slot)) = request.value_slot {
        provider.value_slot(surface, slot).require()?;
        indexes.push(I::TypedSlot);
    }
    if request.semantic_links {
        indexes.push(I::SemanticLink);
    }
    let lookup = match provider {
        ResourceProvider::Http | ResourceProvider::Redis | ResourceProvider::Mysql => {
            LookupPreparation::Indexed
        }
        ResourceProvider::Memcached | ResourceProvider::Motan | ResourceProvider::Kafka => {
            LookupPreparation::ExistingNative
        }
    };
    let selector = match (provider, operation) {
        (ResourceProvider::Mysql, OperationSelector::Any) => SelectorPreparation::SqlTemplate,
        (ResourceProvider::Mysql, OperationSelector::Exact(operation))
            if operation.sql_template() =>
        {
            SelectorPreparation::SqlTemplate
        }
        _ => SelectorPreparation::NativeOperation,
    };
    Ok(ResourcePreparation {
        operation,
        indexes: IndexRequirements::new(indexes),
        lookup,
        selector,
    })
}
