//! Explicit SSE payload scope and case-local, Source-proven identity bindings.
use super::*;

pub(super) fn validate_slot(rule: &Rule) -> Result<()> {
    match &rule.slot {
        Slot::Body => Ok(()),
        Slot::SseData(selector) => {
            let event = selector.event();
            text(event, "sse_data event", 256)?;
            ensure!(
                !event.contains('*') && !event.chars().any(char::is_control),
                "sse_data requires one exact event name"
            );
            if let Some(json_type) = selector.json_type() {
                text(json_type, "sse_data JSON type", 256)?;
                ensure!(
                    !json_type.contains('*') && !json_type.chars().any(char::is_control),
                    "sse_data requires one exact JSON type"
                );
                ensure!(
                    rule.contract
                        .keys()
                        .all(|p| !matches!(p.as_str(), "" | "/type" | "/*")),
                    "SSE JSON type discriminator must remain exact"
                );
            }
            ensure!(rule.codec.is_json(), "sse_data requires codec: json");
            Ok(())
        }
        _ => anyhow::bail!("api.response requires body or an explicit sse_data event slot"),
    }
}

pub(super) fn validate_identity(
    rule: &Rule,
    binding: &str,
    prefix: &str,
    format: IdentityFormat,
) -> Result<()> {
    ensure!(
        rule.surface == Surface::ApiResponse && matches!(rule.slot, Slot::SseData(_)),
        "identity contracts require an api.response sse_data slot"
    );
    ensure!(
        !binding.is_empty()
            && binding.len() <= 64
            && binding
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        "identity binding requires a bounded identifier"
    );
    ensure!(
        prefix.len() <= 256 && !prefix.chars().any(char::is_control),
        "identity prefix requires a bounded literal"
    );
    if let IdentityFormat::Hex(length) = format {
        ensure!(
            (1..=256).contains(&length),
            "hex identity length must be between 1 and 256 characters"
        );
    }
    Ok(())
}

pub(super) fn validate_bindings(rules: &[CompiledRule]) -> Result<()> {
    let mut formats = BTreeMap::new();
    for contract in rules.iter().flat_map(|r| r.rule.contract.values()) {
        if let FieldContract::Identity {
            binding, format, ..
        } = contract.unconditional()
        {
            ensure!(
                formats
                    .insert(binding, format)
                    .is_none_or(|old| old == format),
                "shared identity binding has incompatible formats"
            );
        }
    }
    Ok(())
}
