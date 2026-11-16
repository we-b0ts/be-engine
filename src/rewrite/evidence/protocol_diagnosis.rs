//! Installed native owners interpret their own diagnostic facts.
use super::*;
use traffic_protocol::report::{CodecRegistry, diagnostics::Diagnosis};

pub(super) fn attach(facts: &mut Value, codecs: &CodecRegistry) -> Result<Diagnosis> {
    let mut diagnosis = codecs.diagnose(facts)?;
    let fields = facts
        .as_object_mut()
        .context("dependency facts are not an object")?;
    anyhow::ensure!(
        diagnosis
            .details
            .keys()
            .all(|name| !fields.contains_key(name)),
        "native diagnosis would replace existing dependency facts"
    );
    fields.extend(std::mem::take(&mut diagnosis.details));
    Ok(diagnosis)
}

pub(super) fn has_value_difference(facts: &Value) -> bool {
    crate::protocols::default_providers()
        .report_codecs()
        .has_value_difference(facts)
}

pub(super) fn next_step(diagnosis: &Diagnosis) -> String {
    let mut steps = vec!["Start with the largest endpoint cluster. Execute representative_dependencies_command when present to summarize that case's dependency targets, then select a returned detail_command before proving request or process ownership and response causality in source code.".to_owned()];
    steps.extend(diagnosis.next_steps.iter().cloned());
    steps.join(" ")
}

#[cfg(test)]
mod tests;
