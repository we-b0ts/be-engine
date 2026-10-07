//! Exact-channel PUBLISH UUID rule authoring.
use super::*;
#[derive(Debug, Args)]
pub(super) struct RedisPublishArgs {
    #[arg(long)]
    evidence_id: String,
    #[arg(long)]
    rule_id: String,
    #[arg(long)]
    host: String,
    #[arg(long)]
    port: u16,
    #[arg(long)]
    channel: String,
    /// Zero-based position among ASCII UUID v4 values in the serialized payload.
    #[arg(
        long,
        conflicts_with = "uuid_field",
        required_unless_present = "uuid_field"
    )]
    uuid_index: Option<usize>,
    /// Exact ASCII field marker immediately preceding the UUID (for example host_id).
    #[arg(
        long,
        conflicts_with = "uuid_index",
        required_unless_present = "uuid_index"
    )]
    uuid_field: Option<String>,
    /// Source file/symbol proving the selected UUID's random identity and lifetime.
    #[arg(long)]
    source_evidence: String,
}
pub(super) fn options(args: RedisPublishArgs) -> Result<RewriteDependencyRulePlanOptions> {
    Ok(RewriteDependencyRulePlanOptions {
        evidence_id: args.evidence_id,
        ownership: RewriteDependencyOwnership::RequestOwned,
        name: Some(args.rule_id),
        source_evidence: Some(args.source_evidence),
        selector: RewriteDependencyRuleSelector::RedisPublish {
            selector: traffic_e2e::RedisPublishSelector {
                host: args.host,
                port: args.port,
                channel: args.channel,
                uuid_index: args.uuid_index,
                uuid_field: args.uuid_field,
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: RedisDependencyRuleArgs,
    }
    #[test]
    fn publish_requires_exact_channel_and_explicit_uuid_position() {
        let base = [
            "test",
            "publish",
            "--evidence-id",
            "current",
            "--rule-id",
            "publisher",
            "--host",
            "redis.test",
            "--port",
            "6379",
            "--channel",
            "events",
            "--source-evidence",
            "publisher.py:host_id is generated once via uuid4().hex",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        let cli = Cli::try_parse_from(base.into_iter().chain(["--uuid-index", "0"])).unwrap();
        let plan = super::super::options(cli.args).unwrap();
        assert!(matches!(
            plan.ownership,
            RewriteDependencyOwnership::RequestOwned
        ));
        let RewriteDependencyRuleSelector::RedisPublish { selector } = plan.selector else {
            panic!("wrong PUBLISH selector");
        };
        assert_eq!(selector.channel, "events");
        assert_eq!(selector.uuid_index, Some(0));
        let cli = Cli::try_parse_from(base.into_iter().chain(["--uuid-field", "host_id"])).unwrap();
        let RewriteDependencyRuleSelector::RedisPublish { selector } =
            super::super::options(cli.args).unwrap().selector
        else {
            panic!("wrong PUBLISH selector");
        };
        assert_eq!(selector.uuid_field.as_deref(), Some("host_id"));
        selector.validate().unwrap();
        assert!(
            Cli::try_parse_from(base.into_iter().chain([
                "--uuid-field",
                "host_id",
                "--uuid-index",
                "0"
            ]))
            .is_err()
        );
        let cli = Cli::try_parse_from(base.into_iter().chain(["--uuid-index", "32"])).unwrap();
        let RewriteDependencyRuleSelector::RedisPublish { selector } =
            super::super::options(cli.args).unwrap().selector
        else {
            panic!("wrong PUBLISH selector");
        };
        assert!(selector.validate().is_err());
    }
}
