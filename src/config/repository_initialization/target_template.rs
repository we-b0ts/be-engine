use anyhow::{Result, ensure};

use super::{TARGET_MAIN_TEMPLATE, TARGET_STARTUP_PROBE_TEMPLATE};

pub(super) fn render_target_main(readiness_path: &str, http_backend_port: u16) -> Result<String> {
    ensure!(
        readiness_path.starts_with('/')
            && (readiness_path == "/" || !readiness_path.ends_with('/'))
            && !readiness_path.contains(['?', '#'])
            && !readiness_path.chars().any(char::is_whitespace)
            && !readiness_path
                .split('/')
                .any(|segment| segment.starts_with([':', '*'])),
        "generated target readiness_path must be a literal http-server route: start with '/', use no query, fragment, whitespace, or captures, and omit a trailing '/' except for the root path"
    );
    Ok(TARGET_MAIN_TEMPLATE
        .replace(
            "const DEFAULT_PORT: u16 = 8080;",
            &format!("const DEFAULT_PORT: u16 = {http_backend_port};"),
        )
        .replace(
            "#[http_server::get(\"/healthz\")]",
            &format!("#[http_server::get({readiness_path:?})]"),
        ))
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

#[cfg(test)]
mod tests {
    use super::render_target_main;

    #[test]
    fn readiness_rejects_paths_with_route_or_request_syntax() {
        for path in [
            "healthz",
            "/ready/",
            "/:ready",
            "/ready/*path",
            "/ready?q=1",
            "/ready#ok",
            "/not ready",
        ] {
            let error = render_target_main(path, 8080).unwrap_err();
            assert!(
                error.to_string().contains("literal http-server route"),
                "{path}"
            );
        }
        for path in ["/", "/healthz", "/internal/ready", "/ready\"check"] {
            assert!(render_target_main(path, 8080).is_ok(), "{path}");
        }
    }
}
