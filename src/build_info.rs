/// Version string shared by the `traffic-e2e` and `backend-rewrite` binaries.
pub const BINARY_VERSION: &str = env!("TRAFFIC_E2E_BUILD_VERSION");

pub(crate) const TARGET_RUNTIME_IMAGE: &str = env!("TRAFFIC_E2E_TARGET_RUNTIME_IMAGE");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_version_identifies_the_build_and_target_runtime_contract() {
        assert!(BINARY_VERSION.starts_with(env!("CARGO_PKG_VERSION")));
        assert!(BINARY_VERSION.contains("revision "));
        assert!(BINARY_VERSION.contains(TARGET_RUNTIME_IMAGE));
    }
}
