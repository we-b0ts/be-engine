//! Explicit response payload scope and case-local, Source-proven identities.
use super::*;

pub fn validate_slot(rule: &Rule) -> Result<()> {
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

pub fn validate_identity(rule: &Rule, prefix: &str, format: IdentityFormat) -> Result<()> {
    ensure!(
        matches!(
            (&rule.surface, &rule.slot),
            (Surface::ApiResponse, Slot::Body | Slot::SseData(_))
                | (
                    Surface::DependencyRequest | Surface::DependencyResponse,
                    Slot::SqlField(_) | Slot::RedisValue(_)
                )
        ),
        "identity contracts require a physical SQL/Redis value or an API response payload"
    );
    ensure!(
        prefix.len() <= 256 && !prefix.chars().any(char::is_control),
        "identity prefix requires a bounded literal"
    );
    if let IdentityFormat::BoundedString(length) = format {
        ensure!(
            (1..=1024).contains(&length),
            "identity string length requires 1..1024 bytes"
        );
    }
    if let IdentityFormat::Hex(length) | IdentityFormat::Base64Url(length) = format {
        ensure!(
            (1..=1024).contains(&length),
            "identity token length must be between 1 and 1024 characters"
        );
    }
    Ok(())
}

pub fn validate_identity_scopes(rules: &[CompiledRule]) -> Result<()> {
    for rule in rules {
        for (pointer, contract) in &rule.rule.contract {
            let Some(time) = contract.unconditional().time() else {
                continue;
            };
            let ClockScope::Entity { .. } = &time.clock_scope else {
                continue;
            };
            let identity_pointer = time
                .clock_scope
                .peer_pointer(pointer)
                .context("clock scope identity sibling is absent")?;
            ensure!(
                rules.iter().any(|candidate| {
                    candidate.rule.selector == rule.rule.selector
                        && candidate.rule.slot == rule.rule.slot
                        && candidate.rule.when == rule.rule.when
                        && candidate
                            .rule
                            .contract
                            .get(&identity_pointer)
                            .is_some_and(|identity| {
                                matches!(identity.unconditional(), FieldContract::Identity { .. })
                            })
                }),
                "entity clock_scope requires a declared identity at its sibling pointer in the same payload scope"
            );
        }
    }
    Ok(())
}
