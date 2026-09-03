use super::{TARGET_MAIN_TEMPLATE, TARGET_STARTUP_PROBE_TEMPLATE};

pub(super) fn render_target_main(readiness_path: &str, http_backend_port: u16) -> String {
    TARGET_MAIN_TEMPLATE
        .replace(
            "const DEFAULT_PORT: u16 = 8080;",
            &format!("const DEFAULT_PORT: u16 = {http_backend_port};"),
        )
        .replace(
            "const READINESS_PATH: &str = \"/healthz\";",
            &format!("const READINESS_PATH: &str = {readiness_path:?};"),
        )
}

pub(super) fn render_target_startup_probe() -> String {
    TARGET_STARTUP_PROBE_TEMPLATE
        .replace(
            "__TRAFFIC_E2E_PROBE_ORIGIN_HEADER__",
            crate::network_probe::ORIGIN_HEADER,
        )
        .replace(
            "__TRAFFIC_E2E_PROBE_ORIGIN__",
            crate::network_probe::TARGET_ORIGIN,
        )
}
