//! Policy bindings delegate native SQL template matching to its protocol library.
pub(crate) use traffic_protocol_mysql::value_template::{
    SqlValueTemplate, bounded_statement_tokens, extract,
};
#[cfg(test)]
pub(crate) fn template_matches(template: &str, sql: &str) -> bool {
    SqlValueTemplate::new(template, &[], &[], None).is_ok_and(|template| template.matches(sql))
}
