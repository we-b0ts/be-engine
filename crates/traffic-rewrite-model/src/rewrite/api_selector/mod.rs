pub fn public_api(api: &str) -> &str {
    traffic_engine::recording_api::identity(api)
}

/// Extract the route from a method-qualified recording key.
pub fn route(api: &str) -> &str {
    api.split_once(' ').map_or(api, |(_, path)| path)
}
