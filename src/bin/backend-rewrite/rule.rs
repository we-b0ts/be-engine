//! One rule plan/apply/recover entrypoint; selectors adapt to typed owners.
use std::path::PathBuf;

use anyhow::Result;
use traffic_e2e::{
    RewriteContext, RewriteUnifiedRulePlanOptions, apply_rewrite_rule, plan_rewrite_unified_rule,
    recover_rewrite_rule_plan,
};

use super::{RuleArgs, RuleCommand, print_json};

pub(super) fn run(target_root: PathBuf, args: RuleArgs, pretty: bool) -> Result<()> {
    let context = RewriteContext { target_root };
    match args.command {
        RuleCommand::Plan(args) => {
            let file = args.file;
            let file = file
                .to_str()
                .and_then(|value| value.strip_prefix('@'))
                .map(PathBuf::from)
                .unwrap_or(file);
            let report = plan_rewrite_unified_rule(
                context,
                RewriteUnifiedRulePlanOptions {
                    file,
                    evidence_id: args.evidence_id,
                },
            )?;
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
        assert_eq!(args.file, std::path::PathBuf::from("rules.yaml"));
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
