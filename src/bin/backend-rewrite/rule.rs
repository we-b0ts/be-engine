//! One rule plan/apply/recover entrypoint; selectors adapt to typed owners.
use std::path::PathBuf;

use anyhow::Result;
use traffic_e2e::{
    ResponseBodyCodec, RewriteContext, RewriteRulePlanOptions, RewriteUnifiedRulePlanOptions,
    apply_rewrite_rule, plan_rewrite_rule, plan_rewrite_unified_rule, recover_rewrite_rule_plan,
};

use super::{RuleArgs, RuleCommand, print_json};

pub(super) fn run(target_root: PathBuf, args: RuleArgs, pretty: bool) -> Result<()> {
    let context = RewriteContext { target_root };
    match args.command {
        RuleCommand::Plan(args) => {
            let report = if let Some(file) = args.file {
                let file = file
                    .to_str()
                    .and_then(|value| value.strip_prefix('@'))
                    .map(PathBuf::from)
                    .unwrap_or(file);
                plan_rewrite_unified_rule(
                    context,
                    RewriteUnifiedRulePlanOptions {
                        file,
                        evidence_id: args.evidence_id,
                    },
                )?
            } else {
                plan_rewrite_rule(
                    context,
                    RewriteRulePlanOptions {
                        response_jwts: args.response_jwts,
                        header_dates: args.header_dates,
                        dynamic_value: args.dynamic_value,
                        mysql_time: args.mysql_time,
                        redis_time: args.redis_time,
                        dependency_request: args.dependency_request,
                        evidence_id: args.evidence_id,
                        body_codec: args
                            .body_codec
                            .map(Into::into)
                            .unwrap_or(ResponseBodyCodec::Json),
                        jwt: args.jwt.options()?,
                        time: traffic_e2e::ResponseTimeRule::from_options_with_mode(
                            args.kind.map(Into::into),
                            args.unit,
                            args.timestamp_format,
                            args.timestamp_mode,
                        )?,
                        kind: args.kind.map(Into::into),
                        json_pointer: args.json_pointer,
                        source_evidence: args.source_evidence,
                        source_example: args.source_example,
                        target_example: args.target_example,
                        separator: args.separator,
                        unordered_paths: args.unordered_paths,
                        unordered_joined_string_paths: args.unordered_joined_string_paths,
                        docx_timestamps: args.docx_timestamps,
                    },
                )?
            };
            print_json(&report, pretty)
        }
        RuleCommand::Apply(args) => {
            print_json(&apply_rewrite_rule(context, args.identifier())?, pretty)
        }
        RuleCommand::Recover(args) => print_json(
            &recover_rewrite_rule_plan(context, args.identifier())?,
            pretty,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Cli, RewriteCommand, RuleCommand};
    use clap::Parser;

    #[test]
    fn unified_file_and_reviewed_plan_share_the_existing_rule_entrypoint() {
        let cli = Cli::try_parse_from([
            "backend-rewrite",
            "rule",
            "plan",
            "--file",
            "rules.yaml",
            "--evidence",
            "current",
        ])
        .unwrap();
        let RewriteCommand::Rule(args) = cli.command else {
            panic!("rule command");
        };
        let RuleCommand::Plan(args) = args.command else {
            panic!("plan command");
        };
        assert_eq!(args.file.unwrap(), std::path::PathBuf::from("rules.yaml"));
        for argv in [
            vec!["backend-rewrite", "rule", "apply", "--plan", "reviewed"],
            vec!["backend-rewrite", "rule", "apply", "reviewed"],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            let RewriteCommand::Rule(args) = cli.command else {
                panic!("rule command");
            };
            let RuleCommand::Apply(args) = args.command else {
                panic!("apply command");
            };
            assert_eq!(args.identifier(), "reviewed");
        }
        assert!(
            Cli::try_parse_from([
                "backend-rewrite",
                "rule",
                "plan",
                "--file",
                "rules.yaml",
                "--evidence",
                "current",
                "--kind",
                "random"
            ])
            .is_err()
        );
    }
}
