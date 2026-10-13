//! Bounded API-origin selectors; source proof remains an AI responsibility.
use super::*;

#[derive(Debug, Args)]
#[command(
    after_help = "trigger_source.request_body_json maps JSON Pointers to typed values in the inbound request BODY, never URL query or response. Example: {\"/background\":true}. Capture admits one explicit-column COM_QUERY INSERT and a positive integer identity. GET, exact DEL key sequences, LRANGE and identity-bound EVALSHA remain finite; only unused foreign-case evidence is reclassified. See docs/api-triggered-process-traffic.md."
)]
pub(super) struct ApiTriggeredArgs {
    #[command(flatten)]
    common: DependencyRuleCommonArgs,
    #[arg(long = "port", required = true)]
    ports: Vec<u16>,
    #[arg(long, value_parser = ["GET", "DEL", "LRANGE", "EVALSHA"])]
    command: String,
    /// One key family containing the captured identity, e.g. chat:cancel:{subtask_id}.
    #[arg(long = "key-template", required_unless_present_any = ["key_sequence", "script"])]
    key_templates: Vec<String>,
    /// Ordered DEL keys; every template must bind the same captured identity.
    #[arg(long = "key-sequence-template")]
    key_sequence: Vec<String>,
    /// JSON: sha1, ordered keys, argv_count and zero-based identity_argv_index.
    #[arg(long, value_name = "JSON", value_parser = parse_script)]
    script: Option<traffic_e2e::ApiTriggerRedisScript>,
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

fn parse_script(value: &str) -> std::result::Result<traffic_e2e::ApiTriggerRedisScript, String> {
    serde_json::from_str(value).map_err(|e| format!("invalid script JSON: {e}"))
}

pub(super) fn options(args: ApiTriggeredArgs) -> Result<RewriteDependencyRulePlanOptions> {
    Ok(dependency_rule_options(
        args.common,
        RewriteDependencyRuleSelector::RedisApiTriggered {
            selector: traffic_e2e::ApiTriggeredRedisSelector {
                key_sequence: args.key_sequence,
                script: args.script,
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
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: ApiTriggeredArgs,
    }

    #[test]
    fn explicit_key_sequences_and_scripts_do_not_require_single_key_templates() {
        let base = [
            "test",
            "--evidence-id",
            "current",
            "--ownership",
            "process-owned",
            "--name",
            "background",
            "--source-evidence",
            "jobs.py:finish performs detached cleanup",
            "--port",
            "6379",
            "--trigger-source",
            r#"{"kind":"api","method":"POST","path":"/jobs","capture":{}}"#,
        ];
        let sequence = TestCli::try_parse_from(base.into_iter().chain([
            "--command",
            "DEL",
            "--key-sequence-template",
            "content:{id}",
            "--key-sequence-template",
            "blocks:{id}",
        ]))
        .unwrap();
        assert_eq!(sequence.args.key_sequence.len(), 2);
        assert!(sequence.args.key_templates.is_empty());
        let script = TestCli::try_parse_from(base.into_iter().chain([
            "--command", "EVALSHA", "--script",
            r#"{"sha1":"1111111111111111111111111111111111111111","keys":[{"prefix":"metrics:as-of"}],"argv_count":1,"identity_argv_index":0}"#,
        ])).unwrap();
        assert!(script.args.script.is_some());
        assert!(TestCli::try_parse_from(base.into_iter().chain(["--command", "GET"])).is_err());
    }

    #[test]
    fn source_parser_rejects_query_and_response_aliases() {
        assert!(parse_source(r#"{"kind":"api","method":"POST","path":"/jobs","request_query":{"background":true},"capture":{}}"#).is_err());
        assert!(parse_source(r#"{"kind":"api","method":"POST","path":"/jobs","response_json":{"/background":true},"capture":{}}"#).is_err());
    }
}
