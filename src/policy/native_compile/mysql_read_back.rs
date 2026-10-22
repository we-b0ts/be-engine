//! Admission and field ownership for explicit SQL identity delivery copies.
use super::*;
use crate::policy::MatchSpec;

pub(super) fn validate(rule: &NativeRule) -> Result<()> {
    let NativeEffect::Identity(effect) = &rule.effect else {
        return Ok(());
    };
    ensure!(
        effect.mysql_read_back.len() <= 16,
        "MySQL identity read_back supports at most 16 declarations"
    );
    for entry in &effect.mysql_read_back {
        proof(&entry.proof)?;
        let read = &entry.contract;
        ensure!(
            effect.value_type == IdentityType::String
                && effect
                    .references
                    .iter()
                    .any(|reference| reference.contract.resource == read.resource),
            "MySQL identity read_back requires an existing string identity reference resource"
        );
        ensure!(
            read.resource.protocol == Protocol::Mysql
                && read
                    .resource
                    .database
                    .as_ref()
                    .and_then(crate::policy::Database::name)
                    .is_some(),
            "MySQL identity read_back requires an explicit MySQL database"
        );
        read.resource.endpoint.validate()?;
        text(&read.sql, "MySQL identity read_back SQL", 8192)?;
        text(&read.column, "MySQL identity read_back column", 255)?;
        let selector = value_selector(read);
        crate::replay::validate_mysql_value_selector(&selector)?;
        let analysis = crate::mysql::access::analyze_sql(
            &read
                .sql
                .replace("{{table}}", "__traffic_identity_read_table__"),
        );
        ensure!(
            analysis.statements_complete
                && read
                    .sql
                    .trim_start()
                    .get(..6)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("select")),
            "MySQL identity read_back requires one complete SELECT"
        );
        ensure!(
            (1..=32).contains(&read.json_pointers.len()),
            "MySQL identity read_back requires 1..32 JSON fields"
        );
        let mut fields = BTreeSet::new();
        for pointer in &read.json_pointers {
            compiler::validate_pointer(pointer, true)?;
            ensure!(
                !pointer.is_empty() && fields.insert(pointer),
                "MySQL identity read_back requires unique non-root JSON fields"
            );
        }
        for (pointer, template) in &read.templates {
            text(template, "SQL identity read_back template", 2048)?;
            ensure!(
                fields.contains(pointer)
                    && template.matches("{value}").count() == 1
                    && !template.replace("{value}", "").contains(['{', '}']),
                "SQL identity read_back template must select a declared field and contain exactly one {{value}} slot"
            );
        }
    }
    Ok(())
}

fn value_selector(read: &MysqlIdentityReadBack) -> MatchSpec {
    MatchSpec {
        resource: Some(read.resource.clone()),
        sql: Some(read.sql.clone()),
        tables: read.tables.clone(),
        table_patterns: read.table_patterns.clone(),
        table_series: read.table_series.clone(),
        ..Default::default()
    }
}

pub(super) fn claims(rule: &NativeRule) -> Vec<NativeFieldClaim> {
    let NativeEffect::Identity(effect) = &rule.effect else {
        return vec![];
    };
    let condition = match &effect.capture {
        IdentityCapture::RedisArgument { when, .. } => when.as_ref(),
        _ => None,
    };
    effect
        .mysql_read_back
        .iter()
        .flat_map(|entry| {
            let read = &entry.contract;
            read.json_pointers
                .iter()
                .map(move |pointer| NativeFieldClaim {
                    rule_id: rule.id.clone(),
                    surface: ClaimSurface::DependencyResponse,
                    selector: NativeMatch {
                        api: rule.selector.api.clone(),
                        resource: Some(read.resource.clone()),
                        sql: Some(read.sql.clone()),
                        tables: read.tables.clone(),
                        table_patterns: read.table_patterns.clone(),
                        table_series: read.table_series.clone(),
                        ..Default::default()
                    },
                    when: rule.when.clone(),
                    field_condition: condition.and_then(|when| {
                        when.peer_pointer(pointer)
                            .map(|pointer| OwnedFieldCondition {
                                pointer,
                                when: when.clone(),
                            })
                    }),
                    slot: NativeOwnedSlot::SqlColumn(read.column.clone()),
                    location: OwnedLocation::JsonPointer {
                        pointer: pointer.clone(),
                    },
                    collection: false,
                    hash_field: None,
                })
        })
        .collect()
}
