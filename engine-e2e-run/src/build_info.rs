/// Library version with the committed revision or the explicit revision override.
pub const BINARY_VERSION: &str = env!("TRAFFIC_E2E_BUILD_VERSION");

/// Committed engine revision shared by sibling binaries; no runtime Git or file reads.
pub const ENGINE_FINGERPRINT: &str = env!("TRAFFIC_E2E_ENGINE_FINGERPRINT");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_version_identifies_the_build_and_template_runtime_default() {
        assert!(BINARY_VERSION.starts_with(env!("CARGO_PKG_VERSION")));
        assert!(BINARY_VERSION.contains("revision "));
        assert!(BINARY_VERSION.contains(env!("TRAFFIC_E2E_TARGET_RUNTIME_IMAGE")));
        let revision = ENGINE_FINGERPRINT
            .strip_prefix("engine-revision-v1:")
            .unwrap();
        assert!(BINARY_VERSION.contains(&format!("revision {revision}")));
        assert!(!revision.ends_with("-dirty"));
    }
}
