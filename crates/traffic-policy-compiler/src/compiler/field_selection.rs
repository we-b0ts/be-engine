//! Admission for stable data positions, independent of wire command templates.
use super::*;

pub fn validate(rule: &Rule, resource: &Resource) -> Result<bool> {
    match &rule.slot {
        Slot::SqlField(column) => {
            ensure!(
                resource.protocol == Protocol::Mysql,
                "sql_field requires a MySQL resource"
            );
            let selector = &rule.selector;
            ensure!(
                selector.sql.is_none()
                    && selector.operation.is_none()
                    && selector.path.is_none()
                    && selector.key.is_none()
                    && selector.hash_field.is_none(),
                "sql_field selects a physical table/column without SQL, wire operation, HTTP path or Redis key"
            );
            ensure!(
                !column.is_empty()
                    && column.len() <= 64
                    && column
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_$".contains(&b))
                    && !column.as_bytes()[0].is_ascii_digit(),
                "sql_field requires one physical column identifier"
            );
            text(
                resource
                    .database
                    .as_ref()
                    .and_then(Database::name)
                    .context("sql_field requires a named resource.database")?,
                "resource.database",
                256,
            )?;
            traffic_protocol_mysql::table_selector::TableMatcher::new(
                &selector.tables,
                &selector.table_patterns,
                selector.table_series.as_ref(),
            )?;
            Ok(true)
        }
        Slot::RedisValue(container) => {
            ensure!(
                resource.protocol == Protocol::Redis,
                "redis_value requires a Redis resource"
            );
            let selector = &rule.selector;
            ensure!(
                selector.sql.is_none() && selector.operation.is_none() && selector.path.is_none(),
                "redis_value selects logical values without wire operation, SQL or HTTP path"
            );
            validate_key(
                selector
                    .key
                    .as_ref()
                    .context("redis_value requires a key selector")?,
            )?;
            if let Some(field) = &selector.hash_field {
                ensure!(
                    *container == RedisContainer::Hash,
                    "hash_field requires a hash container"
                );
                validate_key(field)?;
            }
            ensure!(
                matches!(&resource.database, None | Some(Database::Index(0..))),
                "Redis database must be a nonnegative integer"
            );
            ensure!(
                !(rule.codec == Codec::Scalar),
                "Redis values require an explicit JSON or Protobuf codec"
            );
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub fn scalar(rule: &Rule) -> Result<()> {
    if !(rule.codec == Codec::Scalar) {
        return Ok(());
    }
    ensure!(
        matches!(rule.slot, Slot::SqlField(_)),
        "scalar codec requires a physical SQL field"
    );
    ensure!(
        rule.contract.len() == 1 && rule.contract.contains_key(""),
        "scalar codec requires exactly the root field selector ''"
    );
    let contract = match &rule.contract[""] {
        FieldContract::Conditional { when, contract } if when.relative_pointer == "." => {
            contract.as_ref()
        }
        contract => contract,
    };
    ensure!(
        matches!(
            contract,
            FieldContract::Time { .. }
                | FieldContract::Duration { .. }
                | FieldContract::Identity { .. }
                | FieldContract::Policy(_)
                | FieldContract::Exact
        ),
        "scalar codec supports timestamp, duration and identity contracts"
    );
    Ok(())
}
