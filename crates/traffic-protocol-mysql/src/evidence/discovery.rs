//! Bounded physical-field suggestions; observed syntax supplies no business proof.
use crate::sql::{
    bounds,
    field_bindings::{self, FieldIdentity},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use traffic_protocol::evidence::MessageSide;

const FIELD_LIMIT: usize = 128;
const POSITION_LIMIT: usize = 16;
type Key = (String, String, String);

/// Never return SQL text, values, inferred codecs or inferred table families.
/// Live adapters remain the owner of selection and comparison.
pub(super) fn observed(event: &Value, surface: MessageSide) -> Value {
    let database = event["database"].as_str();
    let mut fields = BTreeMap::<Key, (Vec<usize>, usize)>::new();
    let mut omitted = 0;
    let mut unresolved = 0;
    let mut insert = |field: FieldIdentity, position: usize| {
        let Some(database) = field.database.filter(|name| !name.is_empty()) else {
            omitted += 1;
            return;
        };
        let key = (database, field.table, field.column);
        if fields.len() >= FIELD_LIMIT && !fields.contains_key(&key) {
            omitted += 1;
            return;
        }
        let (positions, count) = fields.entry(key).or_default();
        *count += 1;
        if positions.len() < POSITION_LIMIT {
            positions.push(position);
        }
    };
    let request = surface == MessageSide::Request;
    if request {
        if let Some(analysis) = event["sql"]
            .as_str()
            .and_then(bounds::statement)
            .and_then(|tokens| field_bindings::analyze(&tokens, database))
        {
            for binding in &analysis.bindings {
                insert(binding.field.clone(), binding.token_index);
            }
        }
    } else if event["response"]["status"] == "resultset" {
        let columns = event["response"]["columns"].as_array();
        // Full wire origins require no SQL analysis. Old recordings get the
        // same conservative direct-projection prerequisite as Replay.
        let fallback = columns
            .filter(|columns| {
                columns.iter().any(|column| {
                    ["database", "table", "column"]
                        .iter()
                        .any(|key| text(column, key).is_none())
                })
            })
            .and_then(|_| event["sql"].as_str())
            .and_then(bounds::statement)
            .and_then(|tokens| field_bindings::analyze(&tokens, database));
        for (position, column) in columns.into_iter().flatten().enumerate() {
            let origin = match (
                text(column, "database"),
                text(column, "table"),
                text(column, "column"),
            ) {
                (Some(database), Some(table), Some(column)) => Some(FieldIdentity {
                    database: Some(database.into()),
                    table: table.into(),
                    column: column.into(),
                }),
                _ => fallback
                    .as_ref()
                    .and_then(|a| a.projections.as_ref())
                    .filter(|p| Some(p.len()) == columns.map(Vec::len))
                    .and_then(|p| p.get(position))
                    .and_then(Option::as_ref)
                    .filter(|field| {
                        text(column, "table").is_none_or(|table| table == field.table)
                            && text(column, "column").is_none_or(|name| name == field.column)
                            && text(column, "database")
                                .is_none_or(|name| Some(name) == field.database.as_deref())
                    })
                    .cloned(),
            };
            if let Some(origin) = origin {
                insert(origin, position);
            } else {
                unresolved += 1;
            }
        }
    }
    let fields = fields
        .into_iter()
        .map(|((database, table, column), (positions, count))| {
            json!({"database":database,"table":table,"column":column,
            "slot":{"sql_field":column},"observed_positions":positions,
            "positions_omitted":count.saturating_sub(POSITION_LIMIT)})
        })
        .collect::<Vec<_>>();
    json!({"fields":fields,"position_kind":if request {"sql_token"} else {"result_column"},
        "field_limit":FIELD_LIMIT,"positions_per_field_limit":POSITION_LIMIT,
        "unresolved_or_omitted_occurrences":omitted + unresolved,"complete_coverage":false,"source_intent_required":true})
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value[key].as_str().filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unseen_statement_reports_physical_fields_without_sql_values_or_family_guessing() {
        let event = json!({"database":"default_db","sql":"UPDATE other_db.tasks_0042 AS t SET t.updated_at='private-secret' WHERE t.id=123"});
        let observed = observed(&event, MessageSide::Request);
        assert_eq!(observed["fields"].as_array().unwrap().len(), 2);
        assert_eq!(observed["fields"][1]["database"], "other_db");
        assert_eq!(observed["fields"][1]["table"], "tasks_0042");
        assert_eq!(
            observed["fields"][1]["slot"],
            json!({"sql_field":"updated_at"})
        );
        let public = observed.to_string();
        for private in ["private-secret", "123", "table_series", "codec", "UPDATE"] {
            assert!(!public.contains(private), "{private}");
        }
        let ambiguous = json!({"database":"app","sql":"SELECT a.id FROM a JOIN b ON a.id=b.id WHERE updated_at=?"});
        assert!(
            self::observed(&ambiguous, MessageSide::Request)["fields"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn response_uses_wire_origins_and_only_consistent_direct_projection_fallback() {
        let mut event = json!({"database":"default_db","sql":"SELECT t.updated_at AS alias FROM other_db.tasks AS t",
            "response":{"status":"resultset","columns":[{"name":"alias","table":"tasks","column":"updated_at"}]}});
        let result = observed(&event, MessageSide::Response);
        assert_eq!(result["fields"][0]["database"], "other_db");
        event["response"]["columns"][0]["table"] = json!("wrong_table");
        assert!(
            observed(&event, MessageSide::Response)["fields"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        event["response"]["columns"][0] =
            json!({"database":"wire_db","table":"physical","column":"updated_at","name":"alias"});
        event["sql"] = json!("unsupported SQL must not be parsed");
        let result = observed(&event, MessageSide::Response);
        assert_eq!(result["fields"][0]["database"], "wire_db");
        assert_eq!(result["fields"][0]["table"], "physical");
    }

    #[test]
    fn wide_statements_and_repeated_values_have_bounded_suggestions() {
        let assignments = (0..200)
            .map(|index| format!("f{index}={index}"))
            .collect::<Vec<_>>()
            .join(",");
        let event = json!({"database":"app","sql":format!("UPDATE tasks SET {assignments}")});
        let result = observed(&event, MessageSide::Request);
        assert_eq!(result["fields"].as_array().unwrap().len(), FIELD_LIMIT);
        assert_eq!(
            result["unresolved_or_omitted_occurrences"],
            200 - FIELD_LIMIT
        );
        let rows = std::iter::repeat_n("(1)", 40).collect::<Vec<_>>().join(",");
        let event =
            json!({"database":"app","sql":format!("INSERT INTO tasks (updated_at) VALUES {rows}")});
        let result = observed(&event, MessageSide::Request);
        assert_eq!(
            result["fields"][0]["observed_positions"]
                .as_array()
                .unwrap()
                .len(),
            POSITION_LIMIT
        );
        assert_eq!(
            result["fields"][0]["positions_omitted"],
            40 - POSITION_LIMIT
        );
    }
}

pub(super) fn annotations(
    event: &Value,
    side: MessageSide,
) -> anyhow::Result<serde_json::Map<String, Value>> {
    let physical = observed(event, side);
    let prefix = if side == MessageSide::Request {
        "/sql_values"
    } else {
        "/request/sql_values"
    };
    let unavailable = physical["fields"].as_array().is_none_or(Vec::is_empty);
    Ok(serde_json::from_value(json!({
        "source_response_kind":event["response"]["status"],"physical_fields":physical,
        "needs_sql_template":false,"needs_physical_location":unavailable,"needs_schema":false,
        "protected_sql_value_pointers":{
            "value":format!("{prefix}/<sql-token-index>/value"),
            "decoded_json":format!("{prefix}/<sql-token-index>/json/<field-path>"),
            "field":format!("{prefix}/<sql-token-index>/field"),
            "instruction":"Use this witness_id with dependency_witness_query and a token index from physical_fields.fields[].observed_positions. Select a nested JSON field when the SQL value is large. Each statement retains its own physical positions; the candidate is not proof of a match."
        },
        "instruction":"MySQL JSON payloads use root json.fields automatically. Native DATE/DATETIME/TIMESTAMP metadata is inferred when mysql is enabled; historical and invalid scalar inputs stay exact unless a valid differing value is proved. mysql.tables declares remaining scalar formats across databases; recorded and Target physical connection identities must still match. Table patterns contain table names, without a database prefix. No JSON column codec or SQL statement template is needed. Unknown physical origins grant no scalar permission."
    }))?)
}
