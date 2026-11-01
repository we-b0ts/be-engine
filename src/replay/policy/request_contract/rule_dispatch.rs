//! Immutable rule dispatch and native selector preparation, shared by carriers.
use super::*;
use crate::dependency_provider::{
    DependencyProvider, NativeResource, ResourcePreparationRequest, ResourceProvider,
    SelectorPreparation,
};
use crate::protocol_contract::ProtocolKind;
use std::ops::Deref;

type ResourceKey = (ProtocolKind, String, u16);

#[derive(Debug, Default)]
struct Operations {
    any: Vec<usize>,
    exact: BTreeMap<String, Vec<usize>>,
}

#[derive(Debug, Default)]
pub(super) struct NativeDispatch {
    resources: BTreeMap<ResourceKey, Operations>,
    sql: Vec<Option<super::super::sql_template::SqlValueTemplate>>,
}

impl NativeDispatch {
    pub(super) fn prepare(policy: &crate::policy::CompiledPolicy) -> Result<Self> {
        let mut prepared = Self::default();
        for (index, compiled) in policy.native.iter().enumerate() {
            let selector = &compiled.rule.selector;
            let bound_resource = selector
                .resource
                .as_ref()
                .map(|resource| {
                    ResourceProvider::for_protocol(resource.protocol.into())
                        .bind_resource(NativeResource::from_policy(resource)?)
                })
                .transpose()?;
            let resource_preparation = bound_resource
                .as_ref()
                .map(|resource| {
                    ResourceProvider::for_protocol(resource.native.protocol()).prepare(
                        ResourcePreparationRequest {
                            operation: selector.operation.as_deref(),
                            value_slot: None,
                            semantic_links: false,
                        },
                    )
                })
                .transpose()?;
            if compiled
                .execution_plan
                .indexes
                .required
                .contains(&crate::value_contract::plan::IndexRequirement::EndpointOperation)
                && let Some(resource) = bound_resource
            {
                let (host, port) = resource.endpoint();
                let operations = prepared
                    .resources
                    .entry((resource.native.protocol(), host.to_ascii_lowercase(), port))
                    .or_default();
                if let Some(operation) = resource_preparation
                    .as_ref()
                    .and_then(|plan| plan.operation.symbol())
                {
                    if matches!(
                        compiled.rule.effect,
                        crate::policy::NativeEffect::MysqlValues(_)
                    ) && matches!(operation, "COM_QUERY" | "COM_STMT_EXECUTE")
                    {
                        // One SQL value contract owns both native encodings.
                        // Keep that explicit owner visible before automatic
                        // scalar inference can accept an exact historical value.
                        for operation in ["COM_QUERY", "COM_STMT_EXECUTE"] {
                            operations
                                .exact
                                .entry(operation.into())
                                .or_default()
                                .push(index);
                        }
                    } else {
                        operations
                            .exact
                            .entry(operation.to_owned())
                            .or_default()
                            .push(index);
                    }
                } else {
                    operations.any.push(index);
                }
            }
            // Compilation already validates selectors. Keep rejected native
            // templates ineligible, preserving the original strict behavior.
            let prepares_sql = resource_preparation
                .as_ref()
                .is_none_or(|plan| plan.selector == SelectorPreparation::SqlTemplate);
            prepared.sql.push(
                selector
                    .sql
                    .as_deref()
                    .filter(|_| prepares_sql)
                    .and_then(|sql| {
                        super::super::sql_template::SqlValueTemplate::new(
                            sql,
                            &selector.tables,
                            &selector.table_patterns,
                            selector.table_series.as_ref(),
                        )
                        .ok()
                    }),
            );
        }
        Ok(prepared)
    }

    pub(super) fn candidates(
        &self,
        protocol: ProtocolKind,
        target: Option<&TargetKey>,
        operation: &str,
    ) -> RulePositions<'_> {
        let operation = match ResourceProvider::for_protocol(protocol).operation(Some(operation)) {
            Ok(operation) => operation.symbol().expect("an actual operation is exact"),
            Err(_) => return RulePositions::new(&[], &[]),
        };
        let groups = target.and_then(|target| {
            self.resources
                .get(&(protocol, target.host.to_ascii_lowercase(), target.port))
        });
        RulePositions::new(
            groups.map_or(&[], |group| group.any.as_slice()),
            groups
                .and_then(|group| group.exact.get(operation))
                .map_or(&[], Vec::as_slice),
        )
    }

    pub(super) fn sql_matches(&self, index: usize, tokens: &[crate::mysql::sql::Token]) -> bool {
        self.sql
            .get(index)
            .and_then(Option::as_ref)
            .is_some_and(|template| template.matches_tokens(tokens))
    }

    pub(super) fn sql_could_match(&self, index: usize, sql: Option<&str>) -> bool {
        self.sql
            .get(index)
            .and_then(Option::as_ref)
            .zip(sql)
            .is_some_and(|(template, sql)| template.could_match(sql))
    }
}

/// Merge wildcard and operation-specific rules in original compiled order.
pub(super) struct RulePositions<'a> {
    left: &'a [usize],
    right: &'a [usize],
}

impl<'a> RulePositions<'a> {
    fn new(left: &'a [usize], right: &'a [usize]) -> Self {
        Self { left, right }
    }
}

impl Iterator for RulePositions<'_> {
    type Item = usize;
    fn next(&mut self) -> Option<Self::Item> {
        let first = match (self.left.first(), self.right.first()) {
            (Some(left), Some(right)) => (*left).min(*right),
            (Some(value), None) | (None, Some(value)) => *value,
            (None, None) => return None,
        };
        if self.left.first() == Some(&first) {
            self.left = &self.left[1..];
        }
        if self.right.first() == Some(&first) {
            self.right = &self.right[1..];
        }
        Some(first)
    }
}

#[derive(Debug, Default)]
pub(super) struct IndexedRules {
    rules: Vec<ReplayDependencyRule>,
    protocols: [Vec<usize>; 4],
}

impl From<Vec<ReplayDependencyRule>> for IndexedRules {
    fn from(rules: Vec<ReplayDependencyRule>) -> Self {
        let mut protocols: [Vec<usize>; 4] = Default::default();
        for (index, rule) in rules.iter().enumerate() {
            protocols[protocol_index(rule.protocol)].push(index);
        }
        Self { rules, protocols }
    }
}

impl IndexedRules {
    pub(super) fn candidates(
        &self,
        protocol: DependencyProtocol,
    ) -> impl Iterator<Item = &ReplayDependencyRule> {
        self.protocols[protocol_index(protocol)]
            .iter()
            .map(|index| &self.rules[*index])
    }
}

impl Deref for IndexedRules {
    type Target = [ReplayDependencyRule];
    fn deref(&self) -> &Self::Target {
        &self.rules
    }
}

fn protocol_index(protocol: DependencyProtocol) -> usize {
    match protocol {
        DependencyProtocol::Http => 0,
        DependencyProtocol::Mysql => 1,
        DependencyProtocol::Redis => 2,
        DependencyProtocol::Memcached => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_wildcards_merge_in_compiled_order_without_losing_earlier_rules() {
        assert_eq!(
            RulePositions::new(&[0, 3, 8], &[1, 3, 9]).collect::<Vec<_>>(),
            vec![0, 1, 3, 8, 9]
        );
    }

    #[test]
    fn sql_value_owners_are_indexed_for_text_and_binary_execute_commands() {
        let policy = crate::policy::parse_and_compile_policy(
            r#"format: traffic-policy/v3
rules:
  - id: authored-clock
    match:
      resource: {protocol: mysql, endpoint: 'db.test:3306', database: app}
      operation: COM_QUERY
      sql: UPDATE tasks SET stamp=? WHERE id=7
    effect:
      kind: mysql_values
      values:
        0: {relative_time: sql_datetime, utc_offset: '+00:00'}
"#,
        )
        .unwrap();
        let dispatch = NativeDispatch::prepare(&policy).unwrap();
        let target = TargetKey {
            host: "db.test".into(),
            port: 3306,
        };
        for operation in ["COM_QUERY", "COM_STMT_EXECUTE"] {
            assert_eq!(
                dispatch
                    .candidates(ProtocolKind::Mysql, Some(&target), operation)
                    .collect::<Vec<_>>(),
                vec![0]
            );
        }
        assert!(
            dispatch
                .candidates(ProtocolKind::Mysql, Some(&target), "COM_PING")
                .next()
                .is_none()
        );
    }
}
