//! Native HTTP capture views and protocol-independent bounded byte observations.
pub use traffic_model::capture::{capture_body, capture_body_with_original_len};
pub use traffic_protocol_http::body_capture::{capture_case_body, redact_headers};
