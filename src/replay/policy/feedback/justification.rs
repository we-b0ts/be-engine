use anyhow::{Result, ensure};

use super::super::response::{DynamicResponseMechanism, ResponseRuleKind};

pub(super) struct ResponseRuleJustification {
    pub(super) dynamic_mechanisms: Vec<DynamicResponseMechanism>,
    pub(super) source_evidence: Option<String>,
    pub(super) source_example: Option<String>,
    pub(super) target_example: Option<String>,
}

pub(super) fn validate(
    kind: ResponseRuleKind,
    mut dynamic_mechanisms: Vec<DynamicResponseMechanism>,
    source_evidence: Option<String>,
    source_example: Option<String>,
    target_example: Option<String>,
) -> Result<ResponseRuleJustification> {
    match kind {
        ResponseRuleKind::Dynamic => {
            ensure!(
                !dynamic_mechanisms.is_empty(),
                "dynamic response rules require at least one --dynamic-mechanism"
            );
            dynamic_mechanisms.sort();
            dynamic_mechanisms.dedup();
            ensure!(
                !dynamic_mechanisms.contains(&DynamicResponseMechanism::DynamicDerived)
                    || dynamic_mechanisms.len() > 1,
                "dynamic-derived requires the underlying dynamic mechanism"
            );
            validate_text(source_evidence.as_deref(), "--source-evidence", 512)?;
            validate_text(source_example.as_deref(), "--source-example", 1024)?;
            validate_text(target_example.as_deref(), "--target-example", 1024)?;
            ensure!(
                source_example != target_example,
                "dynamic response rules require different --source-example and --target-example values"
            );
        }
        ResponseRuleKind::Counter => {
            ensure!(
                dynamic_mechanisms.is_empty(),
                "--dynamic-mechanism is valid only with --kind dynamic"
            );
            validate_text(source_evidence.as_deref(), "--source-evidence", 512)?;
            validate_text(source_example.as_deref(), "--source-example", 1024)?;
            validate_text(target_example.as_deref(), "--target-example", 1024)?;
            ensure!(
                source_example != target_example,
                "counter response rules require different --source-example and --target-example values"
            );
        }
        ResponseRuleKind::Unordered => {
            ensure!(
                dynamic_mechanisms.is_empty()
                    && source_evidence.is_none()
                    && source_example.is_none()
                    && target_example.is_none(),
                "source and dynamic mechanism evidence is not valid with --kind unordered"
            );
        }
    }
    Ok(ResponseRuleJustification {
        dynamic_mechanisms,
        source_evidence,
        source_example,
        target_example,
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
