//! HTTP dependency ownership, scope, and value-rule CLI projection.
use super::*;

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub(super) struct HttpDependencyRuleArgs {
    #[command(subcommand)]
    mode: Option<HttpDependencyMode>,
    #[arg(long, required = true)]
    evidence_id: Option<String>,
    #[arg(long, value_enum, required = true)]
    ownership: Option<DependencyOwnershipArg>,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    source_evidence: Option<String>,
    #[arg(long, required = true)]
    authority: Option<String>,
    #[arg(long, required = true)]
    method: Option<String>,
    #[arg(long, required = true)]
    path_prefix: Option<String>,
}

#[derive(Debug, Subcommand)]
enum HttpDependencyMode {
    /// Validate a dependency request header against its own request time within five seconds.
    HeaderTimestamp(HttpHeaderTimestampArgs),
    /// Share finite, exactly matched HTTP exchanges across cases of one recording run.
    CrossCase(HttpRequestRuleArgs),
    /// Compare source-proven HTTP request JSON arrays without element-order constraints.
    Unordered(HttpUnorderedArgs),
}

#[derive(Debug, Args)]
struct HttpRequestRuleArgs {
    #[arg(long)]
    evidence_id: String,
    #[arg(long)]
    rule_id: String,
    #[arg(long)]
    host: String,
    #[arg(long)]
    port: u16,
    #[arg(long)]
    method: String,
    #[arg(long)]
    path: String,
    /// Source file/symbol proving the selected dependency rule semantics.
    #[arg(long)]
    source_evidence: String,
}

#[derive(Debug, Args)]
struct HttpUnorderedArgs {
    #[command(flatten)]
    common: HttpRequestRuleArgs,
    /// Non-root JSON Pointer; an entire * segment selects array elements.
    #[arg(long)]
    json_pointer: String,
}

#[derive(Debug, Args)]
struct HttpHeaderTimestampArgs {
    #[command(flatten)]
    common: HttpRequestRuleArgs,
    #[arg(long)]
    header: String,
    #[arg(long, value_enum)]
    timestamp_format: traffic_e2e::ResponseTimestampFormat,
}

pub(super) fn http_options(
    args: HttpDependencyRuleArgs,
) -> Result<RewriteDependencyRulePlanOptions> {
    if let Some(mode) = args.mode {
        let (args, selector) = match mode {
            HttpDependencyMode::CrossCase(args) => {
                let selector = RewriteDependencyRuleSelector::HttpCrossCase {
                    selector: traffic_e2e::HttpCrossCaseSelector {
                        host: args.host.clone(),
                        port: args.port,
                        method: args.method.clone(),
                        path: args.path.clone(),
                    },
                };
                (args, selector)
            }
            HttpDependencyMode::HeaderTimestamp(args) => {
                let selector = RewriteDependencyRuleSelector::HttpHeaderTimestamp {
                    selector: traffic_e2e::HttpHeaderTimestampSelector {
                        host: args.common.host.clone(),
                        port: args.common.port,
                        method: args.common.method.clone(),
                        path: args.common.path.clone(),
                        header: args.header,
                        format: args.timestamp_format,
                    },
                };
                (args.common, selector)
            }
            HttpDependencyMode::Unordered(args) => {
                let selector = RewriteDependencyRuleSelector::HttpUnordered {
                    selector: traffic_e2e::HttpUnorderedSelector {
                        host: args.common.host.clone(),
                        port: args.common.port,
                        method: args.common.method.clone(),
                        path: args.common.path.clone(),
                        pointer: args.json_pointer,
                    },
                };
                (args.common, selector)
            }
        };
        return Ok(RewriteDependencyRulePlanOptions {
            evidence_id: args.evidence_id,
            ownership: RewriteDependencyOwnership::RequestOwned,
            name: Some(args.rule_id),
            source_evidence: Some(args.source_evidence),
            selector,
        });
    }
    let ownership = args.ownership.context("--ownership is required")?;
    ensure!(
        !matches!(ownership, DependencyOwnershipArg::ProcessOwned) || args.name.is_some(),
        "--name is required for process-owned HTTP"
    );
    ensure!(
        matches!(ownership, DependencyOwnershipArg::Unresolved) || args.source_evidence.is_some(),
        "--source-evidence is required"
    );
    Ok(RewriteDependencyRulePlanOptions {
        evidence_id: args.evidence_id.context("--evidence-id is required")?,
        ownership: ownership.into(),
        name: args.name,
        source_evidence: args.source_evidence,
        selector: RewriteDependencyRuleSelector::Http {
            authority: args.authority.context("--authority is required")?,
            method: args.method.context("--method is required")?,
            path_prefix: args.path_prefix.context("--path-prefix is required")?,
        },
    })
}

#[cfg(test)]
mod http_unordered_cli_tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        rule: DependencyRuleArgs,
    }

    #[test]
    fn http_unordered_uses_dependency_value_inputs_without_an_ownership_flag() {
        let cli = Cli::try_parse_from([
            "test",
            "plan",
            "http",
            "unordered",
            "--evidence-id",
            "evidence-current",
            "--rule-id",
            "departments",
            "--host",
            "erp.example.test",
            "--port",
            "80",
            "--method",
            "POST",
            "--path",
            "/membership",
            "--json-pointer",
            "/department_ids",
            "--source-evidence",
            "service.py:216 membership uses an unordered set",
        ])
        .unwrap();
        let DependencyRuleCommand::Plan(args) = cli.rule.command else {
            panic!("expected plan");
        };
        let DependencyPlan::Ownership(options) = args.protocol.try_into().unwrap() else {
            panic!("expected dependency plan");
        };
        assert_eq!(options.ownership, RewriteDependencyOwnership::RequestOwned);
        assert!(
            matches!(options.selector, RewriteDependencyRuleSelector::HttpUnordered { selector } if selector.pointer == "/department_ids")
        );
    }

    #[test]
    fn header_timestamp_cli_uses_fixed_tolerance_and_explicit_format() {
        let args = [
            "test",
            "plan",
            "http",
            "header-timestamp",
            "--evidence-id",
            "current",
            "--rule-id",
            "signing-time",
            "--host",
            "storage.example.test",
            "--port",
            "9100",
            "--method",
            "GET",
            "--path",
            "/bucket/*",
            "--header",
            "x-amz-date",
            "--timestamp-format",
            "amz-date",
            "--source-evidence",
            "sdk.py:build_headers uses UTC time",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        let DependencyRuleCommand::Plan(plan) = cli.rule.command else {
            panic!("plan");
        };
        let DependencyPlan::Ownership(options) = plan.protocol.try_into().unwrap() else {
            panic!("ownership");
        };
        assert_eq!(options.ownership, RewriteDependencyOwnership::RequestOwned);
        assert!(
            matches!(options.selector, RewriteDependencyRuleSelector::HttpHeaderTimestamp { selector }
            if selector.format == traffic_e2e::ResponseTimestampFormat::AmzDate && selector.path == "/bucket/*")
        );
        assert!(Cli::try_parse_from(args.into_iter().chain(["--tolerance", "5s"])).is_err());
    }
}
