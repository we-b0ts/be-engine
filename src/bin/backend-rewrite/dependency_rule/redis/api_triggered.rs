//! Bounded API-origin selectors; source proof remains an AI responsibility.
use super::*;

#[derive(Debug, Args)]
#[command(
    after_help = "trigger_source.request_body_json maps JSON Pointers to typed values in the inbound request BODY, never URL query or response. Example: {\"/background\":true}. Capture admits one explicit-column COM_QUERY INSERT and a positive integer identity. GET, single-key DEL and LRANGE remain finite; only unused foreign-case evidence is reclassified. See docs/api-triggered-process-traffic.md."
)]
pub(super) struct ApiTriggeredArgs {
    #[command(flatten)]
    common: DependencyRuleCommonArgs,
    #[arg(long = "port", required = true)]
    ports: Vec<u16>,
    #[arg(long, value_parser = ["GET", "DEL", "LRANGE"])]
    command: String,
    /// One key family containing the captured identity, e.g. chat:cancel:{subtask_id}.
    #[arg(long = "key-template", required = true)]
    key_templates: Vec<String>,
    /// Exact trailing command arguments; LRANGE requires start and stop. Use --argument=-1.
    #[arg(long = "argument", allow_hyphen_values = true)]
    arguments: Vec<String>,
    /// JSON object with kind=api, method, exact path, optional request_body_json and one capture.
    #[arg(long, value_name = "JSON", value_parser = parse_source)]
    trigger_source: traffic_e2e::ApiTriggerSource,
}

fn parse_source(value: &str) -> std::result::Result<traffic_e2e::ApiTriggerSource, String> {
    serde_json::from_str(value).map_err(|e| format!("invalid trigger_source JSON: {e}"))
}

pub(super) fn options(args: ApiTriggeredArgs) -> Result<RewriteDependencyRulePlanOptions> {
    Ok(dependency_rule_options(
        args.common,
        RewriteDependencyRuleSelector::RedisApiTriggered {
            selector: traffic_e2e::ApiTriggeredRedisSelector {
                ports: args.ports,
                command: args.command,
                key_templates: args.key_templates,
                arguments: args.arguments,
                trigger_source: args.trigger_source,
            },
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_parser_rejects_query_and_response_aliases() {
        assert!(parse_source(r#"{"kind":"api","method":"POST","path":"/jobs","request_query":{"background":true},"capture":{}}"#).is_err());
        assert!(parse_source(r#"{"kind":"api","method":"POST","path":"/jobs","response_json":{"/background":true},"capture":{}}"#).is_err());
    }
}
