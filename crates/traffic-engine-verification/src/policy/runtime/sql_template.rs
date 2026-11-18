//! Policy bindings delegate native SQL template matching to its protocol library.
pub use traffic_protocol_mysql::value_template::SqlValueTemplate;
#[cfg(test)]
pub fn template_matches(template: &str, sql: &str) -> bool {
    SqlValueTemplate::new(template, &[], &[], None).is_ok_and(|template| template.matches(sql))
}
