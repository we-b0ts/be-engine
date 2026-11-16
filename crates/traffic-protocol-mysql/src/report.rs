//! Bounded SQL diagnostics, separate from matching and recorded evidence.
use serde::Serialize;

mod diagnostics;
mod evidence;
mod guidance;
pub use diagnostics::{ConnectionReport, MatchedQueryReport, QueryReport, RecordedExchangeSummary};
pub use evidence::EvidenceCodec;

use crate::sql::{Token, tokens_with_spans};

const PREVIEW_CHARS: usize = 256;
const SELECT_SCAN_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct SqlSummary {
    preview: String,
    fingerprint: String,
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    select_body: Option<TextPreview>,
}

#[derive(Debug, Clone, Serialize)]
struct TextPreview {
    preview: String,
    truncated: bool,
}

impl TextPreview {
    fn new(value: &str) -> Self {
        let mut chars = value.chars();
        let preview = chars.by_ref().take(PREVIEW_CHARS).collect();
        Self {
            preview,
            truncated: chars.next().is_some(),
        }
    }
}

impl SqlSummary {
    pub fn new(sql: &str) -> Self {
        let text = TextPreview::new(sql);
        Self {
            preview: text.preview,
            fingerprint: fnv1a64(sql.as_bytes()),
            truncated: text.truncated,
            select_body: text.truncated.then(|| select_body(sql)).flatten(),
        }
    }
}

// Select the original outer FROM and following clauses, without interpreting
// predicates or using the diagnostic excerpt as SQL matching evidence.
fn select_body(sql: &str) -> Option<TextPreview> {
    if sql.len() > SELECT_SCAN_BYTES {
        return None;
    }
    let (tokens, spans) = tokens_with_spans(sql)?;
    if !tokens.first()?.is("select") {
        return None;
    }
    let mut depth = 0usize;
    let mut from = None;
    let mut end = spans.last()?.end;
    for (index, token) in tokens.iter().enumerate() {
        if token.is(";") {
            if depth != 0 || index + 1 != tokens.len() {
                return None;
            }
            end = spans[index].start;
            continue;
        }
        if token.is("(") {
            depth += 1;
        } else if token.is(")") {
            depth = depth.checked_sub(1)?;
        } else if depth == 0 {
            if token.is("from") && from.is_none() {
                from = Some(spans[index].start);
            }
            if matches!(token, Token::Word(word) if ["union", "intersect", "except"]
                .iter().any(|keyword| word.eq_ignore_ascii_case(keyword)))
            {
                return None;
            }
        }
    }
    if depth != 0 {
        return None;
    }
    Some(TextPreview::new(sql[from?..end].trim_end()))
}

fn fnv1a64(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn long_projection() -> String {
        (0..32)
            .map(|index| format!("subtasks.field_{index} AS subtasks_field_{index}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn summary(sql: &str) -> Value {
        serde_json::to_value(SqlSummary::new(sql)).unwrap()
    }

    #[test]
    fn long_entity_projection_keeps_task_predicate_order_and_lock_visible() {
        let body = "FROM subtasks WHERE subtasks.task_id = 42 \
                    ORDER BY subtasks.message_id ASC, subtasks.created_at ASC LIMIT 1 FOR UPDATE";
        let sql = format!("SELECT {} {body}", long_projection());
        let value = summary(&sql);
        assert_eq!(value["preview"].as_str().unwrap().chars().count(), 256);
        assert!(!value["preview"].as_str().unwrap().contains("WHERE"));
        assert_eq!(value["fingerprint"], fnv1a64(sql.as_bytes()));
        assert_eq!(value["truncated"], true);
        assert_eq!(
            value["select_body"],
            json!({"preview":body,"truncated":false})
        );
    }

    #[test]
    fn excerpt_ignores_projection_literals_comments_and_nested_from() {
        let sql = format!(
            "SELECT 'FROM fake', (SELECT id FROM nested), {} /* FROM comment */ \
             FROM actual WHERE note = 'WHERE fake' ORDER BY id; -- trailing",
            long_projection()
        );
        assert_eq!(
            summary(&sql)["select_body"]["preview"],
            "FROM actual WHERE note = 'WHERE fake' ORDER BY id"
        );
    }

    #[test]
    fn each_excerpt_has_an_independent_unicode_safe_truncation_marker() {
        let sql = format!(
            "SELECT {} FROM subtasks WHERE name = '{}' ORDER BY id",
            long_projection(),
            "查询".repeat(300)
        );
        let value = summary(&sql);
        assert_eq!(value["select_body"]["truncated"], true);
        assert_eq!(
            value["select_body"]["preview"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            256
        );
        assert!(!value.to_string().contains(&sql));
    }

    #[test]
    fn short_sql_preserves_the_existing_summary_shape() {
        let sql = "SELECT id FROM tasks WHERE id = ?";
        assert_eq!(
            summary(sql),
            json!({
                "preview":sql,"fingerprint":fnv1a64(sql.as_bytes()),"truncated":false
            })
        );
    }

    #[test]
    fn unsupported_scans_keep_only_the_original_bounded_excerpt() {
        let columns = long_projection();
        for sql in [
            format!("SELECT {columns} FROM tasks; DELETE FROM tasks"),
            format!("SELECT {columns} FROM tasks WHERE name = 'unterminated"),
            format!("SELECT ({columns} FROM tasks"),
            format!("SELECT ({columns}; SELECT id) FROM tasks"),
            format!("SELECT {columns} FROM tasks UNION SELECT id FROM users"),
            format!("SELECT {columns} FROM tasks INTERSECT SELECT id FROM users"),
            format!("SELECT {columns} FROM tasks except SELECT id FROM users"),
            format!(
                "SELECT {columns} FROM tasks WHERE note = '{}'",
                "x".repeat(SELECT_SCAN_BYTES)
            ),
            format!("UPDATE tasks SET note = '{}'", "x".repeat(300)),
        ] {
            let value = summary(&sql);
            assert!(value.get("select_body").is_none(), "{value}");
            assert_eq!(value["truncated"], true);
            assert_eq!(value["preview"].as_str().unwrap().chars().count(), 256);
            assert_eq!(value["fingerprint"], fnv1a64(sql.as_bytes()));
        }
    }
}
