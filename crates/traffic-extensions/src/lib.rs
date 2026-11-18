//! Application extension catalog. Framework crates depend on the contracts.
use anyhow::Result;
#[allow(unused_imports)] // An empty feature selection has no concrete installations.
use std::sync::Arc;
use std::sync::OnceLock;
use traffic_policy::PolicyRegistry;
use traffic_value::codec::CodecRegistry;

#[cfg(test)]
mod tests;

/// Install native implementations using the application's open identity representation.
#[allow(unused_variables)] // An empty protocol catalog is a supported installation.
pub fn install_protocols<Kind: Copy + PartialEq>(
    registry: &mut traffic_protocol::ProviderRegistry<Kind>,
    identity: impl Fn(&'static str) -> Kind,
) -> Result<()> {
    #[cfg(feature = "protocol-http")]
    registry.register(
        identity("http"),
        Arc::new(traffic_protocol_http::HttpProvider),
    )?;
    #[cfg(feature = "protocol-mysql")]
    registry.register(
        identity("mysql"),
        Arc::new(traffic_protocol_mysql::MysqlProvider),
    )?;
    #[cfg(feature = "protocol-redis")]
    registry.register(
        identity("redis"),
        Arc::new(traffic_protocol_redis::RedisProvider),
    )?;
    #[cfg(feature = "protocol-fixture")]
    registry.register(
        identity(traffic_protocol_fixture::NAME),
        Arc::new(traffic_protocol_fixture::Provider),
    )?;
    Ok(())
}

pub fn codecs() -> &'static CodecRegistry {
    static REGISTRY: OnceLock<CodecRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| build_codecs().expect("extension catalog has unique codec identities"))
}

pub fn policies() -> &'static PolicyRegistry {
    static REGISTRY: OnceLock<PolicyRegistry> = OnceLock::new();
    REGISTRY
        .get_or_init(|| build_policies().expect("extension catalog has unique policy identities"))
}

/// Stable implementation identities used by prepared-value and runtime evidence caches.
pub fn semantics() -> serde_json::Value {
    serde_json::json!({
        "codecs": codecs().descriptors()
            .map(|descriptor| (descriptor.id, descriptor.version))
            .collect::<Vec<_>>(),
        "policies": policies().descriptors()
            .map(|descriptor| (descriptor.id, descriptor.version, descriptor.actions))
            .collect::<Vec<_>>(),
    })
}

#[allow(unused_mut, unused_imports)] // Each installation is independently feature-selected.
pub fn build_codecs() -> Result<CodecRegistry> {
    let mut registry = CodecRegistry::default();
    #[cfg(feature = "codec-json")]
    registry.register(Arc::new(traffic_codec_json::JsonCodec))?;
    #[cfg(feature = "codec-json")]
    registry.register(Arc::new(traffic_codec_json::JsonScalarCodec))?;
    #[cfg(feature = "codec-protobuf")]
    registry.register(Arc::new(traffic_codec_protobuf::ProtobufProvider))?;
    #[cfg(feature = "codec-string")]
    registry.register(Arc::new(traffic_codec_string::StringCodec))?;
    #[cfg(feature = "codec-bytes")]
    registry.register(Arc::new(traffic_codec_bytes::BytesCodec))?;
    Ok(registry)
}

#[allow(unused_mut)] // An installation with no policies is a supported catalog.
pub fn build_policies() -> Result<PolicyRegistry> {
    let mut registry = PolicyRegistry::default();
    #[cfg(feature = "policy-unordered")]
    registry.register(Arc::new(traffic_policy_unordered::UnorderedPolicy))?;
    #[cfg(feature = "policy-unordered")]
    registry.register(Arc::new(traffic_policy_unordered::JoinedStringPolicy))?;
    #[cfg(feature = "policy-time")]
    registry.register(Arc::new(traffic_policy_time::DurationPolicy))?;
    #[cfg(feature = "policy-time")]
    registry.register(Arc::new(traffic_policy_time::TimestampPolicy))?;
    #[cfg(feature = "policy-identity")]
    registry.register(Arc::new(traffic_policy_identity::IdentityPolicy))?;
    #[cfg(feature = "policy-response-rewrite")]
    registry.register(Arc::new(traffic_response_rewrite::ResponseRewritePolicy))?;
    Ok(registry)
}
