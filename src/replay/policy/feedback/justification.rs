use anyhow::{Result, ensure};

use super::super::response::ResponseRuleKind;

pub(super) struct ResponseRuleJustification {
    pub(super) source_evidence: Option<String>,
    pub(super) source_example: Option<String>,
    pub(super) target_example: Option<String>,
    pub(super) separator: Option<String>,
}

pub(super) fn validate(
    kind: ResponseRuleKind,
    source_evidence: Option<String>,
    source_example: Option<String>,
    target_example: Option<String>,
    separator: Option<String>,
) -> Result<ResponseRuleJustification> {
    match kind {
        kind if kind.is_generated() => {
            validate_text(source_evidence.as_deref(), "--source-evidence", 512)?;
            validate_text(source_example.as_deref(), "--source-example", 1024)?;
            validate_text(target_example.as_deref(), "--target-example", 1024)?;
            ensure!(
                source_example != target_example,
                "{kind:?} response rules require different --source-example and --target-example values"
            );
            ensure!(
                separator.is_none(),
                "--separator is not valid for generated response rules"
            );
        }
        ResponseRuleKind::Counter => {
            validate_text(source_evidence.as_deref(), "--source-evidence", 512)?;
            validate_text(source_example.as_deref(), "--source-example", 1024)?;
            validate_text(target_example.as_deref(), "--target-example", 1024)?;
            ensure!(
                source_example != target_example,
                "counter response rules require different --source-example and --target-example values"
            );
            ensure!(
                separator.is_none(),
                "--separator is not valid with --kind counter"
            );
        }
        ResponseRuleKind::Unordered => {
            validate_text(source_evidence.as_deref(), "--source-evidence", 512)?;
            ensure!(
                source_example.is_none() && target_example.is_none(),
                "--source-example and --target-example are not valid with --kind unordered"
            );
            ensure!(
                separator.is_none(),
                "--separator is only valid with --kind unordered-joined-string"
            );
        }
        ResponseRuleKind::UnorderedJoinedString => {
            validate_text(source_evidence.as_deref(), "--source-evidence", 512)?;
            validate_text(separator.as_deref(), "--separator", 16)?;
            ensure!(
                source_example.is_none() && target_example.is_none(),
                "--source-example and --target-example are not valid with --kind unordered-joined-string"
            );
        }
        _ => unreachable!("all response rule kinds are covered"),
    }
    Ok(ResponseRuleJustification {
        source_evidence,
        source_example,
        target_example,
        separator,
    })
}

fn validate_text(value: Option<&str>, label: &str, max_len: usize) -> Result<()> {
    let value = value.ok_or_else(|| anyhow::anyhow!("response rule requires {label}"))?;
    ensure!(
        !value.trim().is_empty(),
        "response rule {label} must not be blank"
    );
    ensure!(
        !value.contains(['\r', '\n']),
        "response rule {label} must be a single line"
    );
    ensure!(
        value.len() <= max_len,
        "response rule {label} exceeds {max_len} bytes"
    );
    Ok(())
}
