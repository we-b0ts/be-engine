//! Static bounds for native input and generated-value declarations.
use anyhow::{Result, ensure};
use std::collections::BTreeSet;
use traffic_policy_schema::native::{
    InputSignedTimestampEffect, RandomEncoding, RedisPubsubKind, RedisPubsubSelector,
};
use traffic_policy_schema::{Database, Protocol};
pub fn signed_timestamp(effect: &InputSignedTimestampEffect) -> Result<()> {
    ensure!(
        (1..=8).contains(&effect.fields.len()),
        "signed timestamp requires 1..8 fields"
    );
    let mut pointers = BTreeSet::new();
    for (name, pointer) in &effect.fields {
        parameter(name)?;
        crate::compiler::validate_pointer(pointer, false)?;
        ensure!(
            !pointer.is_empty() && pointers.insert(pointer),
            "signed fields require distinct non-root JSON pointers"
        );
    }
    ensure!(
        pointers.contains(&effect.timestamp_pointer),
        "signed fields must include the timestamp pointer"
    );
    parameter(&effect.secret_parameter)?;
    ensure!(
        !effect.fields.contains_key(&effect.secret_parameter),
        "secret parameter duplicates a signed field"
    );
    crate::compiler::validate_pointer(&effect.signature_pointer, false)?;
    ensure!(
        !effect.signature_pointer.is_empty(),
        "signature pointer must not select the root"
    );
    let mut all = pointers.into_iter().collect::<Vec<_>>();
    all.push(&effect.signature_pointer);
    for (index, pointer) in all.iter().enumerate() {
        for other in &all[index + 1..] {
            ensure!(
                *pointer != *other
                    && !pointer.starts_with(&format!("{other}/"))
                    && !other.starts_with(&format!("{pointer}/")),
                "signed timestamp fields overlap"
            );
        }
    }
    Ok(())
}

fn parameter(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "signature parameter must be 1..64 ASCII letters, digits or underscores"
    );
    Ok(())
}

pub fn pubsub(selector: &RedisPubsubSelector) -> Result<()> {
    ensure!(
        selector.resource.protocol == Protocol::Redis
            && matches!(selector.resource.database, Some(Database::Index(n)) if n >= 0),
        "Redis Pub/Sub ownership requires a Redis endpoint and exact nonnegative database"
    );
    selector.resource.endpoint.validate()?;
    for value in std::iter::once(&selector.channel).chain(selector.pattern.iter()) {
        ensure!(
            !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control),
            "Redis Pub/Sub channel and pattern require bounded exact bytes"
        );
    }
    ensure!(
        (selector.kind == RedisPubsubKind::Pmessage) == selector.pattern.is_some(),
        "Redis Pub/Sub pmessage requires its exact subscription pattern; other kinds do not"
    );
    ensure!(
        selector
            .resource
            .username
            .as_ref()
            .is_none_or(|name| !name.is_empty()
                && name.len() <= 1024
                && !name.chars().any(char::is_control)),
        "Redis Pub/Sub ownership username must be bounded; absence selects anonymous authentication"
    );
    Ok(())
}
pub fn bounded_random(
    format: &RandomEncoding,
    length: Option<usize>,
    max_length: Option<usize>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        match (format, length, max_length) {
            (RandomEncoding::Hex | RandomEncoding::Base64url, Some(length), None) =>
                (1..=1024).contains(&length),
            (RandomEncoding::Uuid, Some(36), None) => true,
            (RandomEncoding::String, None, Some(max)) => (1..=1024).contains(&max),
            _ => false,
        },
        "random Redis fields require hex/base64url length 1..1024, uuid length 36, or string max_length 1..1024"
    );
    Ok(())
}
pub fn socketio_connect(namespace: &str, pointer: &str) -> Result<()> {
    ensure!(
        namespace.starts_with('/')
            && namespace.len() <= 1024
            && !namespace.chars().any(|c| c.is_control() || c == ','),
        "Socket.IO CONNECT JWT requires an exact bounded namespace"
    );
    crate::compiler::validate_pointer(pointer, false)
}
