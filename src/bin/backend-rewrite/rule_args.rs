//! Request and response verification rule CLI selectors.
use super::{RuleKindArg, jwt_rule};
use clap::{Args, ValueEnum};
use traffic_e2e::{ResponseBodyCodec, ResponseBodyJoinedStringPath, ResponseBodyUnorderedPath};

fn parse_response_body_unordered_path(value: &str) -> Result<ResponseBodyUnorderedPath, String> {
    serde_json::from_str(value).map_err(|error| format!("invalid unordered path JSON: {error}"))
}

fn parse_response_body_joined_string_path(
    value: &str,
) -> Result<ResponseBodyJoinedStringPath, String> {
    serde_json::from_str(value).map_err(|error| format!("invalid joined-string path JSON: {error}"))
}

fn parse_docx_timestamp(value: &str) -> Result<traffic_e2e::DocxTimestampRule, String> {
    serde_json::from_str(value).map_err(|error| format!("invalid DOCX timestamp JSON: {error}"))
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum ResponseBodyCodecArg {
    Json,
    Protobuf,
    Hessian2,
    Docx,
}

impl From<ResponseBodyCodecArg> for ResponseBodyCodec {
    fn from(value: ResponseBodyCodecArg) -> Self {
        match value {
            ResponseBodyCodecArg::Json => Self::Json,
            ResponseBodyCodecArg::Protobuf => Self::Protobuf,
            ResponseBodyCodecArg::Hessian2 => Self::Hessian2,
            ResponseBodyCodecArg::Docx => Self::Docx,
        }
    }
}

#[derive(Debug, Args)]
pub(super) struct RulePlanArgs {
    /// Signed JWT in a JSON HTTP response. Declares algorithm, key source and optional UUID v4 jti.
    #[arg(long = "response-jwt", value_name = "RULE_JSON", value_parser = parse_response_jwt, conflicts_with_all = ["header_dates", "dynamic_value", "dependency_request", "request_kind", "kind", "json_pointer", "unordered_paths", "unordered_joined_string_paths", "docx_timestamps"])]
    pub(super) response_jwts: Vec<traffic_e2e::ResponseJwtRule>,
    /// Source-proven Redis argument, HTTP multipart, or MySQL result timestamp contract.
    #[arg(long, value_name = "RULE_JSON", value_parser = parse_dependency_request, conflicts_with_all = ["dynamic_value", "header_dates", "request_kind", "kind", "json_pointer", "unordered_paths", "unordered_joined_string_paths", "docx_timestamps"])]
    pub(super) dependency_request: Option<serde_json::Value>,
    /// Source-proven captured identity rule; references are automatic across scoped endpoints.
    #[arg(long, value_name = "RULE_JSON", value_parser = parse_dynamic_value, conflicts_with_all = ["header_dates", "request_kind", "kind", "json_pointer", "unordered_paths", "unordered_joined_string_paths", "docx_timestamps"])]
    pub(super) dynamic_value: Option<traffic_e2e::DynamicValueRule>,
    /// Date location in an HTTP response header (including filename / filename*).
    #[arg(long = "header-date", value_name = "RULE_JSON", value_parser = parse_header_date, conflicts_with_all = ["request_kind", "kind", "json_pointer", "unordered_paths", "unordered_joined_string_paths", "docx_timestamps"])]
    pub(super) header_dates: Vec<traffic_e2e::ResponseHeaderDateRule>,
    #[command(flatten)]
    pub(super) jwt: jwt_rule::JwtArgs,
    #[arg(long)]
    pub(super) evidence_id: String,
    /// Body codec. JSON uses --kind, protobuf/Hessian2 use typed paths, and DOCX uses --docx-timestamp.
    #[arg(long, value_enum, required_unless_present_any = ["request_kind", "header_dates", "dynamic_value", "dependency_request", "response_jwts"])]
    pub(super) body_codec: Option<ResponseBodyCodecArg>,
    /// JSON response-rule kind. Omit for protobuf and Hessian2 typed-body rules.
    #[arg(
        long,
        value_enum,
        conflicts_with_all = ["unordered_paths", "unordered_joined_string_paths"]
    )]
    pub(super) kind: Option<RuleKindArg>,
    #[arg(long, value_enum)]
    pub(super) unit: Option<traffic_e2e::ResponseDurationUnit>,
    #[arg(long, value_enum)]
    pub(super) timestamp_format: Option<traffic_e2e::ResponseTimestampFormat>,
    #[arg(long)]
    pub(super) json_pointer: Option<String>,
    #[arg(long)]
    pub(super) source_evidence: Option<String>,
    #[arg(long)]
    pub(super) source_example: Option<String>,
    #[arg(long)]
    pub(super) target_example: Option<String>,
    #[arg(long, required_if_eq("kind", "unordered-joined-string"))]
    pub(super) separator: Option<String>,
    /// Typed protobuf/Hessian2 unordered selector encoded as one JSON object.
    #[arg(
        long = "unordered-path",
        value_name = "PATH_JSON",
        value_parser = parse_response_body_unordered_path,
        conflicts_with_all = [
            "kind",
            "json_pointer",
            "source_evidence",
            "source_example",
            "target_example",
            "separator"
        ]
    )]
    pub(super) unordered_paths: Vec<ResponseBodyUnorderedPath>,
    /// Typed protobuf/Hessian2 joined-string selector encoded as one JSON object.
    #[arg(
        long = "unordered-joined-string-path",
        value_name = "PATH_JSON",
        value_parser = parse_response_body_joined_string_path,
        conflicts_with_all = [
            "kind",
            "json_pointer",
            "source_evidence",
            "source_example",
            "target_example",
            "separator"
        ]
    )]
    pub(super) unordered_joined_string_paths: Vec<ResponseBodyJoinedStringPath>,
    /// DOCX timestamp selector encoded as one JSON object.
    #[arg(
        long = "docx-timestamp",
        value_name = "RULE_JSON",
        value_parser = parse_docx_timestamp,
        conflicts_with_all = ["kind", "json_pointer", "unordered_paths", "unordered_joined_string_paths"]
    )]
    pub(super) docx_timestamps: Vec<traffic_e2e::DocxTimestampRule>,
}

fn parse_dependency_request(value: &str) -> Result<serde_json::Value, String> {
    let value: serde_json::Value = serde_json::from_str(value)
        .map_err(|error| format!("invalid dependency request JSON: {error}"))?;
    if !value.is_object() {
        return Err("dependency request rule requires a JSON object".into());
    }
    Ok(value)
}

fn parse_dynamic_value(value: &str) -> Result<traffic_e2e::DynamicValueRule, String> {
    serde_json::from_str(value).map_err(|error| format!("invalid dynamic value rule: {error}"))
}

fn parse_header_date(value: &str) -> Result<traffic_e2e::ResponseHeaderDateRule, String> {
    serde_json::from_str(value)
        .map_err(|error| format!("invalid response header date rule: {error}"))
}

fn parse_response_jwt(value: &str) -> Result<traffic_e2e::ResponseJwtRule, String> {
    serde_json::from_str(value).map_err(|_| "invalid JWT response rule JSON".into())
}

#[cfg(test)]
mod generated_tests {
    use clap::Parser;
    #[test]
    fn dependency_request_cli_parses_an_object_and_rejects_other_json_values() {
        use super::super::{Cli, RewriteCommand, RuleCommand};
        let raw = r#"{"protocol":"redis","redis":{"commands":[]}}"#;
        let cli = Cli::try_parse_from([
            "backend-rewrite",
            "rule",
            "plan",
            "--evidence-id",
            "current",
            "--dependency-request",
            raw,
        ])
        .unwrap();
        let RewriteCommand::Rule(args) = cli.command else {
            panic!("rule command")
        };
        let RuleCommand::Plan(plan) = args.command else {
            panic!("plan command")
        };
        assert_eq!(
            plan.dependency_request,
            Some(serde_json::from_str(raw).unwrap())
        );
        for raw in ["null", "[]", "42", "true", "\"object\"", "{broken"] {
            assert!(
                Cli::try_parse_from([
                    "backend-rewrite",
                    "rule",
                    "plan",
                    "--evidence-id",
                    "current",
                    "--dependency-request",
                    raw,
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn generated_value_rules_do_not_require_a_body_codec_and_reject_mixed_families() {
        let dependency = r#"{"id":"write-contract","protocol":"redis","target":{"host":"redis","port":6379},"redis":{"key":"one","commands":[{"command":"SET","argument_values":{"1":{"json":{"/at":{"time":"preserve_relative","format":"unix_seconds"}}}}}]}}"#;
        let header = r#"{"header":"content-disposition","parameter":"filename","format":"%Y-%m-%d","timezone":"+00:00"}"#;
        let dynamic = r#"{"id":"name","targets":[{"host":"db","port":3306}],"capture":{"protocol":"mysql","target":{"host":"db","port":3306},"database":"app","sql":"SELECT id FROM t WHERE name=?","value_index":0}}"#;
        let response_jwt = r#"{"pointer":"/access_token","algorithm":"HS256","signing_key_source":{"kind":"target_env","name":"SECRET_KEY"},"source_evidence":"Connector:issue"}"#;
        let response_url_jwt = r#"{"pointer":"/downloadUrl","url_query_param":"token","expires_at":"/expiresAt","algorithm":"HS256","signing_key_source":{"kind":"target_env","name":"SECRET_KEY"},"dynamic_claims":[{"pointer":"/nonce","format":"base64url","decoded_bytes":16}],"source_evidence":"Download:descriptor"}"#;
        for (flag, spec) in [
            ("--response-jwt", response_jwt),
            ("--response-jwt", response_url_jwt),
            ("--header-date", header),
            ("--dynamic-value", dynamic),
            ("--dependency-request", dependency),
        ] {
            assert!(
                super::super::Cli::try_parse_from([
                    "backend-rewrite",
                    "rule",
                    "plan",
                    "--evidence-id",
                    "current",
                    flag,
                    spec,
                    "--source-evidence",
                    "Generator:current value"
                ])
                .is_ok()
            );
        }
        for conflicting in [
            "--kind",
            "--request-kind",
            "--dynamic-value",
            "--dependency-request",
            "--header-date",
        ] {
            assert!(
                super::super::Cli::try_parse_from([
                    "backend-rewrite",
                    "rule",
                    "plan",
                    "--evidence-id",
                    "current",
                    "--response-jwt",
                    response_jwt,
                    conflicting,
                    "jwt"
                ])
                .is_err()
            );
        }
        assert!(
            super::super::Cli::try_parse_from([
                "backend-rewrite",
                "rule",
                "plan",
                "--evidence-id",
                "current",
                "--header-date",
                header,
                "--dynamic-value",
                dynamic
            ])
            .is_err()
        );
        assert!(
            super::super::Cli::try_parse_from([
                "backend-rewrite",
                "rule",
                "plan",
                "--evidence-id",
                "current",
                "--header-date",
                header,
                "--kind",
                "timestamp"
            ])
            .is_err()
        );
    }
}
